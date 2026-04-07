import json
import os
from typing import Optional

import requests
from openai import OpenAI

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
USE_LLM = bool(HF_TOKEN and HF_TOKEN != "dummy")

TASKS = os.getenv("SUPPLY_CHAIN_TASK", "easy,medium,hard,confusion").split(",")
ALL_MAX_STEPS = {"easy": 12, "medium": 20, "hard": 30, "confusion": 20}
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")

client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN) if USE_LLM else None

VALID_ACTIONS = {
    "list_packages",
    "get_audit_output",
    "get_git_log",
    "inspect_package",
    "check_publish_history",
    "check_maintainer",
    "trace_network",
    "check_similarity",
    "get_dependency_tree",
    "submit_findings",
}


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    err = error.replace("\n", " ") if error else "null"
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} "
        f"done={str(done).lower()} error={err}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: list[float]) -> None:
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.3f} rewards={','.join(f'{r:.2f}' for r in rewards)}",
        flush=True,
    )


def env_reset(task: str) -> dict:
    resp = requests.post(f"{ENV_BASE_URL}/reset", json={"task": task}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def env_step(session_id: str, action: str, params: dict) -> dict:
    resp = requests.post(
        f"{ENV_BASE_URL}/step",
        json={"session_id": session_id, "action": action, "params": params},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def extract_packages_from_tree(tree: dict, packages: set[str]) -> None:
    for key, value in tree.items():
        pkg_name = key.split("@")[0]
        packages.add(pkg_name)
        if isinstance(value, dict):
            extract_packages_from_tree(value, packages)


def package_names_from_observation(observation: dict) -> list[str]:
    result = observation.get("result", {})
    pkgs = result.get("packages", [])
    names: list[str] = []

    for item in pkgs:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict) and "name" in item:
            names.append(item["name"])

    return names


def analyze_evidence(history: list[dict]) -> dict:
    evidence = {
        "suspicious_packages": [],
        "signals": {},
        "all_packages": [],
    }

    for entry in history:
        result = entry.get("result", {})
        action = entry.get("action")

        if action == "list_packages" and isinstance(result, dict):
            packages = result.get("packages", [])
            evidence["all_packages"] = [
                p["name"] if isinstance(p, dict) else p for p in packages
            ]

        elif action == "get_dependency_tree" and isinstance(result, dict):
            tree = result.get("tree", {})
            all_pkgs: set[str] = set()
            extract_packages_from_tree(tree, all_pkgs)
            evidence["all_packages"].extend(list(all_pkgs))
            evidence["all_packages"] = list(set(evidence["all_packages"]))

        pkg_name = entry.get("params", {}).get("name")
        if not pkg_name:
            continue

        if pkg_name not in evidence["signals"]:
            evidence["signals"][pkg_name] = []

        if action == "inspect_package" and isinstance(result, dict):
            scripts = result.get("install_scripts", {})
            if scripts:
                evidence["signals"][pkg_name].append("has_install_script")
                script_text = str(scripts).lower()
                if any(
                    token in script_text
                    for token in ["curl", "wget", "http://", "https://", "exec", "eval", ".get("]
                ):
                    evidence["signals"][pkg_name].append("suspicious_script")
                    evidence["suspicious_packages"].append(pkg_name)

            source = str(result.get("source_preview", "") or "").lower()
            if any(token in source for token in ["curl", "wget", "http.get", "exec", "eval"]):
                evidence["signals"][pkg_name].append("suspicious_code")
                evidence["suspicious_packages"].append(pkg_name)

            downloads = result.get("weekly_downloads")
            if downloads is not None and downloads < 10000:
                evidence["signals"][pkg_name].append("low_downloads")

        elif action == "check_publish_history" and isinstance(result, dict):
            analysis = str(result.get("analysis", "") or "")
            if "ANOMALIES" in analysis or "gap" in analysis.lower():
                evidence["signals"][pkg_name].append("publish_anomaly")
                evidence["suspicious_packages"].append(pkg_name)

        elif action == "check_maintainer" and isinstance(result, dict):
            result_text = str(result).lower()
            if "warning" in result_text or "flag" in result_text:
                evidence["signals"][pkg_name].append("maintainer_suspicious")
                evidence["suspicious_packages"].append(pkg_name)

        elif action == "trace_network" and isinstance(result, dict):
            if result.get("flagged_requests", 0) > 0:
                for known_pkg in evidence["all_packages"]:
                    if known_pkg in evidence["signals"] and "has_install_script" in evidence["signals"][known_pkg]:
                        evidence["signals"][known_pkg].append("suspicious_network")
                        evidence["suspicious_packages"].append(known_pkg)

    evidence["suspicious_packages"] = list(set(evidence["suspicious_packages"]))
    return evidence


def classify_attack_vector(pkg_name: str, signals: list[str]) -> str:
    signal_set = set(signals)
    lowered = pkg_name.lower()

    if "publish_anomaly" in signal_set and "maintainer_suspicious" in signal_set:
        return "hijacked_maintainer"

    if any(token in lowered for token in ["company", "internal", "private", "corp"]):
        if "suspicious_script" in signal_set or "suspicious_network" in signal_set:
            return "dependency_confusion"

    if "suspicious_network" in signal_set:
        return "poisoned_transitive_dependency"

    if "low_downloads" in signal_set and "has_install_script" in signal_set:
        return "typosquat"

    if "suspicious_script" in signal_set or "suspicious_code" in signal_set:
        return "malicious_install_script"

    return "malicious_install_script"


def rule_based_action(task: str, step: int, observation: dict, history: list[dict]) -> tuple[str, dict]:
    if step == 1:
        return "list_packages", {}
    if step == 2:
        return "trace_network", {"build_step": "all"}
    if step == 3:
        return "get_dependency_tree", {"depth": 4}

    evidence = analyze_evidence(history)
    visible_packages = set(package_names_from_observation(observation))
    known_packages = set(evidence["all_packages"]) | visible_packages

    if step <= 15 and known_packages:
        inspected = {
            entry.get("params", {}).get("name")
            for entry in history
            if entry.get("action") == "inspect_package"
        }
        for pkg in sorted(known_packages):
            if pkg and pkg not in inspected:
                return "inspect_package", {"name": pkg}

    suspicious = evidence["suspicious_packages"]
    if suspicious:
        findings = {
            pkg: classify_attack_vector(pkg, evidence["signals"].get(pkg, []))
            for pkg in suspicious
        }
        return "submit_findings", {"packages": suspicious, "attack_vectors": findings}

    for pkg in sorted(known_packages):
        if pkg in evidence["signals"] and "has_install_script" in evidence["signals"][pkg]:
            return "submit_findings", {
                "packages": [pkg],
                "attack_vectors": {pkg: "malicious_install_script"},
            }

    return "submit_findings", {"packages": [], "attack_vectors": {}}


def normalize_params(action: str, params: dict) -> dict:
    if not isinstance(params, dict):
        return {}

    if action in {"inspect_package", "check_publish_history", "check_maintainer"}:
        if "name" not in params:
            if "package_name" in params:
                params["name"] = params.pop("package_name")
            elif "package" in params:
                params["name"] = params.pop("package")

    if action == "get_dependency_tree":
        params["depth"] = int(params.get("depth", 4))

    if action == "trace_network" and "build_step" not in params:
        params["build_step"] = "all"

    return params


def normalize_attack_vectors(params: dict) -> dict:
    if not isinstance(params, dict):
        return {}

    attack_vectors = params.get("attack_vectors")
    if not isinstance(attack_vectors, dict):
        return params

    normalized = {}
    for pkg, vec in attack_vectors.items():
        if not isinstance(vec, str):
            normalized[pkg] = vec
            continue

        value = vec.lower().strip().replace(" ", "_").replace("-", "_")

        if "typo" in value and "squat" in value:
            normalized[pkg] = "typosquat"
        elif "hijack" in value or ("maintainer" in value and "compromise" in value):
            normalized[pkg] = "hijacked_maintainer"
        elif "transitive" in value or ("poison" in value and "dependency" in value):
            normalized[pkg] = "poisoned_transitive_dependency"
        elif "install" in value and "script" in value:
            normalized[pkg] = "malicious_install_script"
        elif "confusion" in value or "namespace" in value:
            normalized[pkg] = "dependency_confusion"
        else:
            normalized[pkg] = value

    params["attack_vectors"] = normalized
    return params


def llm_action(task: str, step: int, observation: dict, history: list[dict]) -> tuple[str, dict]:
    if client is None:
        raise RuntimeError("LLM client not configured")

    visible_packages = package_names_from_observation(observation)

    system_prompt = f"""
You are investigating a software supply chain attack.

Return ONLY valid JSON:
{{"action":"<one valid action>","params":{{...}}}}

Valid actions:
{json.dumps(sorted(VALID_ACTIONS))}

Rules:
- Do not invent action names.
- Do not invent package names.
- Prefer investigation before submit_findings.
- Use only these attack vectors:
  ["typosquat","hijacked_maintainer","poisoned_transitive_dependency","malicious_install_script","dependency_confusion"]
""".strip()

    user_payload = {
        "task": task,
        "step": step,
        "visible_packages": visible_packages,
        "observation": observation,
        "history": history[-6:],
    }

    completion = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload)},
        ],
        temperature=0.2,
        max_tokens=220,
    )

    text = (completion.choices[0].message.content or "").strip()
    text = text.replace("```json", "").replace("```", "").strip()

    try:
        parsed = json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Model did not return JSON")
        parsed = json.loads(text[start:end + 1])

    action = parsed["action"]
    if action not in VALID_ACTIONS:
        raise ValueError(f"Invalid action: {action}")

    params = normalize_params(action, normalize_attack_vectors(parsed.get("params", {})))
    return action, params


def choose_action(task: str, step: int, observation: dict, history: list[dict]) -> tuple[str, dict]:
    if not USE_LLM or client is None:
        return rule_based_action(task, step, observation, history)

    try:
        return llm_action(task, step, observation, history)
    except Exception as exc:
        print(f"[DEBUG] LLM fallback triggered: {exc}", flush=True)
        return rule_based_action(task, step, observation, history)


BENCHMARK = "supply-chain-forensics"


def run_task(task: str) -> None:
    max_steps = ALL_MAX_STEPS[task]
    effective_model = MODEL_NAME if USE_LLM else "rule-based"
    log_start(task=task, env=BENCHMARK, model=effective_model)

    rewards: list[float] = []
    steps_taken = 0
    final_score = 0.0
    success = False
    history: list[dict] = []

    try:
        reset_resp = env_reset(task)
        session_id = reset_resp["session_id"]
        observation = reset_resp["observation"]
        done = reset_resp["done"]

        for step in range(1, max_steps + 1):
            if done:
                break

            action, params = choose_action(task, step, observation, history)

            try:
                step_resp = env_step(session_id, action, params)
            except Exception:
                action, params = rule_based_action(task, step, observation, history)
                step_resp = env_step(session_id, action, params)

            observation = step_resp["observation"]
            reward = step_resp["reward"]
            done = step_resp["done"]

            rewards.append(reward)
            steps_taken = step

            log_step(
                step=step,
                action=f"{action}({json.dumps(params)})",
                reward=reward,
                done=done,
                error=observation.get("last_action_error"),
            )

            history.append(
                {
                    "step": step,
                    "action": action,
                    "params": params,
                    "reward": reward,
                    "done": done,
                    "result": observation.get("result"),
                }
            )

            if action == "submit_findings" and isinstance(observation.get("result"), dict):
                final_score = observation["result"].get("score", 0.0)

            if done:
                break

        success = final_score >= 0.5

    except Exception as exc:
        print(f"[DEBUG] Fatal error: {exc}", flush=True)

    finally:
        final_score = min(0.999, max(0.001, final_score))
        log_end(success=success, steps=steps_taken, score=final_score, rewards=rewards)


def main() -> None:
    for task in TASKS:
        task = task.strip()
        if task in ALL_MAX_STEPS:
            run_task(task)


if __name__ == "__main__":
    main()
