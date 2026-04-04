"""
Supply Chain Attack Forensics — Core Environment
================================================
OpenEnv-compliant environment where an AI agent investigates
compromised software dependencies. Simulates real-world
supply chain attacks: typosquats, hijacked maintainer accounts,
and poisoned transitive dependencies.
"""

import json
import os
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


# ─── Typed Models ────────────────────────────────────────────────────────────

class ActionRequest(BaseModel):
    action: str = Field(..., description="Action name")
    params: dict[str, Any] = Field(default_factory=dict, description="Action parameters")


class Observation(BaseModel):
    step: int
    action_taken: str
    result: Any
    packages_flagged: list[str]
    steps_remaining: int
    last_action_error: Optional[str] = None


class StepResult(BaseModel):
    observation: Observation
    reward: float
    done: bool
    info: dict[str, Any] = Field(default_factory=dict)


class StateResponse(BaseModel):
    task: str
    difficulty: str
    description: str
    project: dict[str, Any]
    step: int
    max_steps: int
    packages_flagged: list[str]
    findings_submitted: bool
    done: bool


# ─── Environment ─────────────────────────────────────────────────────────────

SCENARIOS_DIR = Path(__file__).parent / "scenarios"

TASK_MAP = {
    "easy":   "typosquat_detection",
    "medium": "hijacked_maintainer",
    "hard":   "transitive_dependency_poisoning",
    "confusion": "confusion",
}

MAX_STEPS = {
    "easy":   12,
    "medium": 20,
    "hard":   30,
    "confusion": 20,
}

# Small penalty per step — encourages efficient investigation
STEP_COST = 0.02


class SupplyChainEnv:
    """
    OpenEnv environment simulating supply chain attack forensics.

    The agent receives a software project's dependency manifest, git history,
    audit output, and network logs from a build. Some dependencies are
    compromised. The agent uses targeted actions (each costing a step) to
    investigate and must submit findings: which packages are compromised and
    what the attack vector is.

    Grading: precision × recall on flagged packages + attack vector bonus.
    """

    def __init__(self, difficulty: str = "easy"):
        if difficulty not in TASK_MAP:
            raise ValueError(f"difficulty must be one of {list(TASK_MAP.keys())}")
        self.difficulty = difficulty
        self.task = TASK_MAP[difficulty]
        self._scenario: dict[str, Any] = {}
        self._state: dict[str, Any] = {}
        self._reset()

    # public API

    def reset(self) -> StepResult:
        """Reset the environment to a fresh episode."""
        self._reset()
        obs = self._make_observation(
            action_taken="reset",
            result=self._initial_briefing(),
            error=None
        )
        return StepResult(observation=obs, reward=0.0, done=False, info={})

    def step(self, action_request: ActionRequest) -> StepResult:
        """Execute one investigative action."""
        if self._state["done"]:
            obs = self._make_observation("none", "Episode already ended.", error="Episode is done.")
            return StepResult(observation=obs, reward=0.0, done=True)

        self._state["step"] += 1
        step_reward = -STEP_COST  # efficiency penalty

        try:
            result, extra_reward = self._dispatch(action_request)
            error = None
        except ActionError as e:
            result = str(e)
            extra_reward = 0.0
            error = str(e)

        reward = step_reward + extra_reward
        self._state["cumulative_reward"] += reward

        # Check termination
        done = (
            self._state["findings_submitted"]
            or self._state["step"] >= self._state["max_steps"]
        )
        self._state["done"] = done

        obs = self._make_observation(
            action_taken=f"{action_request.action}({json.dumps(action_request.params)})",
            result=result,
            error=error
        )
        return StepResult(
            observation=obs,
            reward=round(reward, 4),
            done=done,
            info={"step": self._state["step"], "cumulative_reward": self._state["cumulative_reward"]}
        )

    def state(self) -> StateResponse:
        """Return current environment state (non-consuming)."""
        return StateResponse(
            task=self.task,
            difficulty=self.difficulty,
            description=self._scenario["description"],
            project=self._scenario["project"],
            step=self._state["step"],
            max_steps=self._state["max_steps"],
            packages_flagged=list(self._state["packages_flagged"]),
            findings_submitted=self._state["findings_submitted"],
            done=self._state["done"],
        )

    #action dispatch

    def _dispatch(self, req: ActionRequest) -> tuple[Any, float]:
        """Route action to handler, return (result, bonus_reward)."""
        handlers = {
            "inspect_package":        self._action_inspect_package,
            "check_publish_history":  self._action_check_publish_history,
            "check_maintainer":       self._action_check_maintainer,
            "trace_network":          self._action_trace_network,
            "check_similarity":       self._action_check_similarity,
            "get_dependency_tree":    self._action_get_dependency_tree,
            "list_packages":          self._action_list_packages,
            "get_audit_output":       self._action_get_audit_output,
            "get_git_log":            self._action_get_git_log,
            "submit_findings":        self._action_submit_findings,
        }
        if req.action not in handlers:
            raise ActionError(
                f"Unknown action '{req.action}'. "
                f"Valid actions: {', '.join(handlers.keys())}"
            )
        return handlers[req.action](req.params)

    #Action handlers 

    def _action_list_packages(self, params: dict) -> tuple[Any, float]:
        """List all packages in the manifest."""
        manifest = self._scenario["package_manifest"]
        deps = manifest.get("dependencies") or manifest.get("requires") or {}
        return {
            "project": self._scenario["project"]["name"],
            "packages": [
                {"name": k, "version": v}
                for k, v in deps.items()
            ],
            "note": "Use inspect_package, check_publish_history, or check_maintainer to investigate specific packages."
        }, 0.0

    def _action_get_audit_output(self, params: dict) -> tuple[Any, float]:
        """Get the npm/pip audit output for the project."""
        return {
            "audit_output": self._scenario["audit_output"],
            "warning": "Audit tools only detect known CVEs. Novel or recent attacks will not appear here."
        }, 0.0

    def _action_get_git_log(self, params: dict) -> tuple[Any, float]:
        """Get the project's git commit log."""
        return {"git_log": self._scenario["git_log"]}, 0.0

    def _action_inspect_package(self, params: dict) -> tuple[Any, float]:
        """Inspect package source, metadata, and install scripts."""
        name = self._require_param(params, "name")
        pkg = self._get_package(name)

        result = {
            "name": name,
            "version": pkg.get("version"),
            "description": pkg.get("description"),
            "author": pkg.get("author"),
            "maintainers": pkg.get("maintainers"),
            "published": pkg.get("published"),
            "weekly_downloads": pkg.get("weekly_downloads"),
            "homepage": pkg.get("homepage"),
            "repository": pkg.get("repository"),
            "install_scripts": pkg.get("install_scripts", {}),
        }

        if "source_preview" in pkg:
            result["source_preview"] = pkg["source_preview"]

        # Small reward hint if agent inspects a suspicious package's install scripts
        bonus = 0.0
        if pkg.get("suspicious") and pkg.get("install_scripts"):
            bonus = 0.05  # Found something relevant

        return result, bonus

    def _action_check_publish_history(self, params: dict) -> tuple[Any, float]:
        """Check version publish history and look for anomalies."""
        name = self._require_param(params, "name")
        pkg = self._get_package(name)

        result = {
            "name": name,
            "current_version": pkg.get("version"),
            "published_current": pkg.get("published"),
            "weekly_downloads": pkg.get("weekly_downloads"),
        }

        if "version_history" in pkg:
            result["version_history"] = pkg["version_history"]
            result["analysis"] = self._analyze_publish_history(pkg["version_history"])
        else:
            result["version_history"] = [
                {"version": pkg.get("version"), "date": pkg.get("published")}
            ]
            result["analysis"] = "No anomalies detected in publish history."

        bonus = 0.0
        if pkg.get("suspicious") and "version_history" in pkg:
            bonus = 0.08  # Good investigation move

        return result, bonus

    def _action_check_maintainer(self, params: dict) -> tuple[Any, float]:
        """Check maintainer account activity and profile."""
        name = self._require_param(params, "name")
        pkg = self._get_package(name)
        maintainers = pkg.get("maintainers", [])

        if not maintainers:
            return {"name": name, "maintainers": [], "note": "No maintainer data available."}, 0.0

        result = {
            "name": name,
            "maintainers": maintainers,
            "account_count": len(maintainers),
        }

        # Provide richer data for suspicious packages
        if pkg.get("suspicious") and pkg.get("attack_vector") == "hijacked_maintainer":
            result["maintainer_details"] = {
                maintainers[0]: {
                    "account_age": "3 years",
                    "last_publish": pkg.get("published"),
                    "total_packages": 1,
                    "github_activity": {
                        "last_commit": "2023-08-01",
                        "status": "DORMANT — no activity since August 2023",
                        "stars": 12,
                        "followers": 3
                    },
                    "flag": "Account dormant for 6+ months before this publish. Consistent with credential theft."
                }
            }
            result["warning"] = "Maintainer account shows signs of compromise: dormant for 19 weeks, IP region changed at publish time."
        elif pkg.get("suspicious") and pkg.get("attack_vector") == "typosquat":
            result["maintainer_details"] = {
                maintainers[0]: {
                    "account_age": "94 days",
                    "total_packages": 1,
                    "github_activity": "Account created 94 days ago. No other packages. No followers.",
                    "flag": "Single-package account created shortly before this package was published."
                }
            }
        elif pkg.get("suspicious") and pkg.get("attack_vector") == "poisoned_transitive_dependency":
            result["maintainer_details"] = {
                maintainers[0]: {
                    "account_age": "4 years",
                    "last_publish": pkg.get("published"),
                    "total_packages": 3,
                    "github_activity": {
                        "last_commit": "2023-08-01",
                        "status": "DORMANT — no activity since August 2023",
                        "note": "Account has 4 years of consistent activity then went completely silent in August 2023."
                    },
                    "flag": "Consistent with account takeover: long-term legitimate history, then sudden silence before malicious publish."
                }
            }
        else:
            result["maintainer_details"] = {
                m: {"status": "active", "verified": True}
                for m in maintainers[:2]
            }

        bonus = 0.05 if pkg.get("suspicious") else 0.0
        return result, bonus

    def _action_trace_network(self, params: dict) -> tuple[Any, float]:
        """Trace network calls made during a specific build step."""
        build_step = params.get("build_step", "all")
        logs = self._scenario.get("network_logs", {})

        if build_step == "all":
            all_logs = []
            for step_name, entries in logs.items():
                all_logs.extend(entries)
            flagged = [e for e in all_logs if e.get("flagged")]
            result = {
                "build_step": "all",
                "total_requests": len(all_logs),
                "flagged_requests": len(flagged),
                "entries": all_logs
            }
        else:
            # Find matching step
            matched = None
            for step_name, entries in logs.items():
                if build_step.lower() in step_name.lower():
                    matched = (step_name, entries)
                    break
            if matched:
                flagged = [e for e in matched[1] if e.get("flagged")]
                result = {
                    "build_step": matched[0],
                    "entries": matched[1],
                    "flagged_requests": len(flagged)
                }
            else:
                result = {
                    "build_step": build_step,
                    "error": f"No network logs found for step '{build_step}'. Available steps: {list(logs.keys())}",
                    "entries": []
                }

        # Bonus if agent finds flagged network requests.
        flagged_found = any(e.get("flagged") for entries in logs.values() for e in entries)
        bonus = 0.08 if flagged_found and build_step == "all" else 0.05 if flagged_found else 0.0
        return result, bonus

    def _action_check_similarity(self, params: dict) -> tuple[Any, float]:
        """Check if a package name is similar to a known legitimate package."""
        name = self._require_param(params, "name")
        reference = params.get("reference", None)

        # Get all packages we know about for comparison
        known_legit = [
            "lodash", "axios", "express", "react", "webpack", "babel",
            "eslint", "typescript", "jest", "prettier", "rollup", "vite"
        ]

        pkg = self._scenario.get("packages", {}).get(name)

        results = []
        compare_against = [reference] if reference else known_legit

        for legit in compare_against:
            distance = self._levenshtein(name, legit)
            similarity = 1.0 - (distance / max(len(name), len(legit)))
            results.append({
                "package": name,
                "compared_to": legit,
                "edit_distance": distance,
                "similarity": round(similarity, 3),
                "flag": distance <= 3 and name != legit
            })

        results.sort(key=lambda x: x["edit_distance"])
        suspicious_matches = [r for r in results if r["flag"]]

        bonus = 0.0
        if pkg and pkg.get("suspicious") and pkg.get("attack_vector") == "typosquat" and suspicious_matches:
            bonus = 0.10  # Agent correctly identified the typosquat signal

        return {
            "name": name,
            "closest_matches": results[:5],
            "suspicious_matches": suspicious_matches,
            "verdict": "SUSPICIOUS — likely typosquat" if suspicious_matches else "No suspicious similarity detected"
        }, bonus

    def _action_get_dependency_tree(self, params: dict) -> tuple[Any, float]:
        """Get the full dependency tree up to N levels deep."""
        depth = min(int(params.get("depth", 2)), 5)

        if "dependency_tree" in self._scenario:
            tree = self._scenario["dependency_tree"]
            result = {
                "depth_requested": depth,
                "tree": self._prune_tree(tree, depth),
                "note": "Use inspect_package or check_publish_history on any transitive dependency to investigate it."
            }
            # For hard scenario, bonus if agent goes deep enough to find the malicious package
            if self.difficulty == "hard" and depth >= 4:
                result["discovery"] = "At depth 4, found: async-stat-collector@3.1.6 (dependency of build-perf-metrics)"
                return result, 0.08
        else:
            manifest = self._scenario["package_manifest"]
            deps = manifest.get("dependencies") or manifest.get("requires") or {}
            result = {
                "depth_requested": depth,
                "tree": {
                    f"{self._scenario['project']['name']}": {
                        f"{k}@{v}": {} for k, v in deps.items()
                    }
                },
                "note": "Direct dependencies only. These packages may themselves have transitive dependencies."
            }

        return result, 0.0

    def _action_submit_findings(self, params: dict) -> tuple[Any, float]:
        """
        Submit final findings. Terminates the episode.

        params:
          - packages: list of package names flagged as compromised
          - attack_vectors: dict mapping package name → attack vector string
        """
        flagged = params.get("packages", [])
        vectors = params.get("attack_vectors", {})

        if not isinstance(flagged, list):
            raise ActionError("'packages' must be a list of package names.")

        self._state["packages_flagged"] = list(flagged)
        self._state["findings_submitted"] = True

        # Grade
        score, breakdown = self._grade(flagged, vectors)

        return {
            "submission_received": True,
            "packages_flagged": flagged,
            "attack_vectors": vectors,
            "score": round(score, 4),
            "breakdown": breakdown
        }, score  # The full score is the bonus reward on submission

    #  Grading section 

    def _grade(self, flagged: list[str], vectors: dict[str, str]) -> tuple[float, dict]:
        """
        Compute precision × recall on flagged packages.
        Bonus: +0.1 for each correct attack vector.
        Clamped to [0, 1].
        """
        ground_truth = self._scenario["ground_truth"]
        true_positives_set = set(ground_truth["compromised_packages"])
        flagged_set = set(flagged)

        tp = len(flagged_set & true_positives_set)
        fp = len(flagged_set - true_positives_set)
        fn = len(true_positives_set - flagged_set)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        # Vector bonus
        vector_bonus = 0.0
        vector_results = {}
        true_vectors = ground_truth.get("attack_vectors", {})
        for pkg, vec in vectors.items():
            if pkg in true_vectors:
                correct = self._normalize_vector(vec) == self._normalize_vector(true_vectors[pkg])
                vector_results[pkg] = {"submitted": vec, "correct": correct}
                if correct:
                    vector_bonus += 0.1
            else:
                vector_results[pkg] = {"submitted": vec, "correct": False, "note": "Package not in ground truth"}

        # Efficiency bonus: reward faster solving
        steps_used = self._state["step"]
        max_steps = self._state["max_steps"]
        optimal = ground_truth.get("max_steps_for_full_score", max_steps)
        efficiency = max(0.0, 1.0 - max(0, steps_used - optimal) / (max_steps - optimal + 1))
        efficiency_bonus = 0.1 * efficiency if f1 > 0.5 else 0.0

        total = min(1.0, f1 * 0.8 + vector_bonus + efficiency_bonus)

        return total, {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "true_positives": list(flagged_set & true_positives_set),
            "false_positives": list(flagged_set - true_positives_set),
            "false_negatives": list(true_positives_set - flagged_set),
            "vector_results": vector_results,
            "vector_bonus": round(vector_bonus, 4),
            "efficiency_bonus": round(efficiency_bonus, 4),
            "total_score": round(total, 4)
        }

    #Internal helpers

    def _reset(self):
        scenario_path = SCENARIOS_DIR / f"{self.difficulty}.json"
        with open(scenario_path) as f:
            self._scenario = json.load(f)
        self._state = {
            "step": 0,
            "max_steps": MAX_STEPS[self.difficulty],
            "packages_flagged": [],
            "findings_submitted": False,
            "done": False,
            "cumulative_reward": 0.0,
            "started_at": time.time(),
        }

    def _initial_briefing(self) -> dict:
        manifest = self._scenario["package_manifest"]
        deps = manifest.get("dependencies") or manifest.get("requires") or {}
        return {
            "briefing": self._scenario["description"],
            "project": self._scenario["project"],
            "package_count": len(deps),
            "packages": list(deps.keys()),
            "available_actions": [
                "list_packages()",
                "get_audit_output()",
                "get_git_log()",
                "inspect_package(name='<pkg>')",
                "check_publish_history(name='<pkg>')",
                "check_maintainer(name='<pkg>')",
                "trace_network(build_step='all')",
                "check_similarity(name='<pkg>', reference='<known_pkg>')",
                "get_dependency_tree(depth=<1-5>)",
                "submit_findings(packages=['<pkg>'], attack_vectors={'<pkg>': '<vector>'})",
            ],
            "valid_attack_vectors": [
                "typosquat",
                "hijacked_maintainer",
                "poisoned_transitive_dependency",
                "malicious_install_script",
                "dependency_confusion"
            ],
            "budget": f"{self._state['max_steps']} steps remaining"
        }

    def _make_observation(self, action_taken: str, result: Any, error: Optional[str]) -> Observation:
        return Observation(
            step=self._state["step"],
            action_taken=action_taken,
            result=result,
            packages_flagged=list(self._state["packages_flagged"]),
            steps_remaining=self._state["max_steps"] - self._state["step"],
            last_action_error=error,
        )

    def _get_package(self, name: str) -> dict:
        packages = self._scenario.get("packages", {})
        # Check direct manifest packages
        if name in packages:
            return packages[name]
        # Check transitive deps
        for pkg_name, pkg_data in packages.items():
            if "dependencies" in pkg_data:
                if name in pkg_data["dependencies"]:
                    return packages.get(name, {"version": pkg_data["dependencies"][name]})
        raise ActionError(
            f"Package '{name}' not found. "
            f"Known packages: {', '.join(packages.keys())}"
        )

    def _analyze_publish_history(self, history: list[dict]) -> str:
        if len(history) < 2:
            return "Insufficient history to analyze."
        flags = []
        for entry in history:
            if entry.get("note"):
                flags.append(entry["note"])
        if flags:
            return "ANOMALIES DETECTED: " + " | ".join(flags)
        return "No anomalies in publish timeline."

    def _prune_tree(self, tree: dict, max_depth: int, current_depth: int = 0) -> dict:
        if current_depth >= max_depth:
            return {"(truncated — increase depth to see more)": {}}
        return {
            k: self._prune_tree(v, max_depth, current_depth + 1)
            for k, v in tree.items()
        }

    @staticmethod
    def _normalize_vector(v: str) -> str:
        return v.lower().strip().replace(" ", "_").replace("-", "_")

    @staticmethod
    def _require_param(params: dict, key: str) -> Any:
        if key not in params or not params[key]:
            raise ActionError(f"Missing required parameter: '{key}'")
        return params[key]

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return SupplyChainEnv._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]


class ActionError(Exception):
    pass
