"""Supply Chain Attack Forensics — Hybrid Inference Script (FINAL)"""
import json
import os
from typing import Optional
import requests
from openai import OpenAI

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN", "dummy")
TASK = os.getenv("SUPPLY_CHAIN_TASK", "easy")
BENCHMARK = "supply-chain-forensics"
MAX_STEPS = {"easy": 12, "medium": 20, "hard": 30, "confusion": 20}[TASK]
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")
client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
VALID_ACTIONS = {"list_packages", "get_audit_output", "get_git_log", "inspect_package", "check_publish_history", "check_maintainer", "trace_network", "check_similarity", "get_dependency_tree", "submit_findings"}

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    err = error.replace("\n", " ") if error else "null"
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={err}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: list[float]) -> None:
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={','.join(f'{r:.2f}' for r in rewards)}", flush=True)

def env_reset(task: str) -> dict:
    return requests.post(f"{ENV_BASE_URL}/reset", json={"task": task}, timeout=30).json()

def env_step(session_id: str, action: str, params: dict) -> dict:
    return requests.post(f"{ENV_BASE_URL}/step", json={"session_id": session_id, "action": action, "params": params}, timeout=30).json()

def extract_packages_from_tree(tree: dict, packages: set) -> None:
    """Recursively extract all package names from dependency tree"""
    for key, value in tree.items():
        pkg_name = key.split('@')[0]
        packages.add(pkg_name)
        if isinstance(value, dict):
            extract_packages_from_tree(value, packages)

def analyze_evidence(history: list[dict]) -> dict:
    evidence = {"suspicious_packages": [], "signals": {}, "all_packages": []}
    
    for entry in history:
        result = entry.get("result", {})
        action = entry.get("action")
        
        if action == "list_packages" and isinstance(result, dict):
            packages = result.get("packages", [])
            evidence["all_packages"] = [p["name"] if isinstance(p, dict) else p for p in packages]
        
        if action == "get_dependency_tree" and isinstance(result, dict):
            tree = result.get("tree", {})
            all_pkgs = set()
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
                script_content = str(scripts)
                if any(w in script_content.lower() for w in ["curl", "wget", "http://", "https://", "exec", "eval", ".get("]):
                    evidence["signals"][pkg_name].append("suspicious_script")
                    evidence["suspicious_packages"].append(pkg_name)
            
            source = result.get("source_preview", "")
            if source and any(w in source.lower() for w in ["curl", "wget", "http.get", "exec", "eval"]):
                evidence["signals"][pkg_name].append("suspicious_code")
                evidence["suspicious_packages"].append(pkg_name)
            
            downloads = result.get("weekly_downloads")
            if downloads is not None and downloads < 10000:
                evidence["signals"][pkg_name].append("low_downloads")
        
        elif action == "check_publish_history" and isinstance(result, dict):
            analysis = result.get("analysis", "")
            if "ANOMALIES" in analysis or "gap" in analysis.lower():
                evidence["signals"][pkg_name].append("publish_anomaly")
                evidence["suspicious_packages"].append(pkg_name)
        
        elif action == "check_maintainer" and isinstance(result, dict):
            if "warning" in result or "flag" in str(result).lower():
                evidence["signals"][pkg_name].append("maintainer_suspicious")
                evidence["suspicious_packages"].append(pkg_name)
        
        elif action == "trace_network" and isinstance(result, dict):
            if result.get("flagged_requests", 0) > 0:
                for p in evidence["all_packages"]:
                    if p in evidence["signals"] and "has_install_script" in evidence["signals"][p]:
                        evidence["signals"][p].append("suspicious_network")
                        evidence["suspicious_packages"].append(p)
    
    evidence["suspicious_packages"] = list(set(evidence["suspicious_packages"]))
    return evidence

def classify_attack_vector(pkg_name: str, signals: list[str]) -> str:
    signal_set = set(signals)
    if "suspicious_script" in signal_set or "suspicious_code" in signal_set:
        if any(p in pkg_name.lower() for p in ["company", "internal", "private", "corp"]):
            return "dependency_confusion"
        if "publish_anomaly" in signal_set and "maintainer_suspicious" in signal_set:
            return "hijacked_maintainer"
        if "suspicious_network" in signal_set:
            return "poisoned_transitive_dependency"
        return "malicious_install_script"
    if "publish_anomaly" in signal_set and "maintainer_suspicious" in signal_set:
        return "hijacked_maintainer"
    if "low_downloads" in signal_set and "has_install_script" in signal_set:
        return "typosquat"
    if "suspicious_network" in signal_set:
        return "poisoned_transitive_dependency"
    return "malicious_install_script"

def rule_based_action(task: str, step: int, observation: dict, history: list[dict]) -> tuple[str, dict]:
    if step == 1:
        return "list_packages", {}
    if step == 2:
        return "trace_network", {"build_step": "all"}
    if step == 3:
        return "get_dependency_tree", {"depth": 4}
    
    evidence = analyze_evidence(history)
    all_packages = evidence["all_packages"]
    
    if step <= 15 and all_packages:
        inspected = {e.get("params", {}).get("name") for e in history if e.get("action") == "inspect_package"}
        for pkg in all_packages:
            if pkg not in inspected:
                return "inspect_package", {"name": pkg}
    
    suspicious = evidence["suspicious_packages"]
    if suspicious:
        findings = {pkg: classify_attack_vector(pkg, evidence["signals"].get(pkg, [])) for pkg in suspicious}
        return "submit_findings", {"packages": suspicious, "attack_vectors": findings}
    
    for pkg in all_packages:
        if pkg in evidence["signals"] and "has_install_script" in evidence["signals"][pkg]:
            return "submit_findings", {"packages": [pkg], "attack_vectors": {pkg: "malicious_install_script"}}
    
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
        v = vec.lower().strip().replace(" ", "_").replace("-", "_")
        if "typo" in v and "squat" in v:
            normalized[pkg] = "typosquat"
        elif "hijack" in v or ("maintainer" in v and "compromise" in v):
            normalized[pkg] = "hijacked_maintainer"
        elif "transitive" in v or ("poison" in v and "dependency" in v):
            normalized[pkg] = "poisoned_transitive_dependency"
        elif "install" in v and "script" in v:
            normalized[pkg] = "malicious_install_script"
        elif "confusion" in v or "namespace" in v:
            normalized[pkg] = "dependency_confusion"
        else:
            normalized[pkg] = v
    params["attack_vectors"] = normalized
    return params

def llm_action(task: str, step: int, observation: dict, history: list[dict]) -> tuple[str, dict]:
    system_prompt = """Investigate supply chain attacks. Choose next action. Return JSON: {"action": "<name>", "params": {...}}"""
    completion = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": json.dumps({"step": step, "observation": observation, "history": history[-6:]})}],
        temperature=0, max_tokens=300)
    text = (completion.choices[0].message.content or "").strip().replace("```json", "").replace("```", "").strip()
    try:
        parsed = json.loads(text)
    except:
        start, end = text.find("{"), text.rfind("}")
        parsed = json.loads(text[start:end + 1]) if start != -1 and end != -1 else {}
    action = parsed["action"]
    params = normalize_params(action, normalize_attack_vectors(parsed.get("params", {})))
    if action not in VALID_ACTIONS:
        raise ValueError(f"Invalid action: {action}")
    return action, params

def choose_action(task: str, step: int, observation: dict, history: list[dict]) -> tuple[str, dict]:
    try:
        return llm_action(task, step, observation, history)
    except Exception as exc:
        print(f"[DEBUG] LLM fallback triggered: {exc}", flush=True)
        return rule_based_action(task, step, observation, history)

def main() -> None:
    log_start(task=TASK, env=BENCHMARK, model=MODEL_NAME)
    rewards, steps_taken, final_score, success, history = [], 0, 0.0, False, []
    try:
        reset_resp = env_reset(TASK)
        session_id, observation, done = reset_resp["session_id"], reset_resp["observation"], reset_resp["done"]
        for step in range(1, MAX_STEPS + 1):
            if done:
                break
            action, params = choose_action(TASK, step, observation, history)
            try:
                step_resp = env_step(session_id, action, params)
            except:
                action, params = rule_based_action(TASK, step, observation, history)
                step_resp = env_step(session_id, action, params)
            observation, reward, done = step_resp["observation"], step_resp["reward"], step_resp["done"]
            rewards.append(reward)
            steps_taken = step
            log_step(step=step, action=f"{action}({json.dumps(params)})", reward=reward, done=done, error=observation.get("last_action_error"))
            history.append({"step": step, "action": action, "params": params, "reward": reward, "done": done, "result": observation.get("result")})
            if action == "submit_findings" and isinstance(observation.get("result"), dict):
                final_score = observation["result"].get("score", 0.0)
            if done:
                break
        success = final_score >= 0.5
    except Exception as exc:
        print(f"[DEBUG] Fatal error: {exc}", flush=True)
    finally:
        log_end(success=success, steps=steps_taken, score=final_score, rewards=rewards)

if __name__ == "__main__":
    main()
