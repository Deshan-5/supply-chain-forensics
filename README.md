---
title: Supply Chain Forensics
emoji: 🛡️
colorFrom: gray
colorTo: indigo
sdk: docker
app_file: app.py
pinned: false
---

# Supply Chain Forensics

OpenEnv benchmark where an AI agent investigates compromised software dependencies.

On March 31, 2026, the axios npm package was hijacked through stolen maintainer credentials. Backdoored versions deployed a cross-platform RAT on every machine running `npm install`. `npm audit` did not flag it, because it only detects known vulnerabilities.

Similar failures occurred in:
- ua-parser-js (account takeover)
- event-stream (malicious dependency injection)
- SolarWinds (build pipeline compromise)
- XZ Utils (deep transitive backdoor)

These incidents share a pattern: the attack is not a known CVE. It emerges through behavior, context, and dependency relationships.

This environment places an agent in that setting. It is given:
- a project with a dependency graph
- a set of investigation actions
- a limited step budget

The agent must:
- identify compromised packages
- classify the attack vector

The task isn't pattern matching. It requires multi step investigation across metadata, dependency structure, and runtime signals.

---

## Environment

### Observation
Each step returns:
- project context and briefing
- current step and remaining budget
- list of packages
- results of the last action
- packages flagged so far

### Actions
- list_packages()
- inspect_package(name)
- check_publish_history(name)
- check_maintainer(name)
- trace_network(build_step)
- get_dependency_tree(depth)
- check_similarity(name, reference)
- submit_findings(packages, attack_vectors)

### Attack Vectors
- typosquat
- hijacked_maintainer
- poisoned_transitive_dependency
- malicious_install_script
- dependency_confusion

---

## Tasks

- easy — Typosquat detection  
- medium — Maintainer compromise 
- hard — Transitive dependency poisoning  
- confusion — Dependency confusion  

---

## Evaluation

Score ∈ [0, 1]

- F1 score for compromised package detection  
- bonus for correct attack vector classification  
- step penalty and efficiency bonus  

---

## Baseline Results

| Task | Score |
|------|------:|
| Easy | 0.900 |
| Medium | 0.900 |
| Hard | 0.881 |
| Confusion | 0.885 |

---

## Run locally

pip install -r requirements.txt  
python -m uvicorn app:app --host 127.0.0.1 --port 7860  

Test:

curl -X POST http://127.0.0.1:7860/reset -H "Content-Type: application/json" -d '{"task":"easy"}'

---

## Baseline Inference

export ENV_BASE_URL=http://127.0.0.1:7860  

for task in easy medium hard confusion; do  
  SUPPLY_CHAIN_TASK=$task python3 inference.py  


---

## Deployment

https://deshan-5-supply-chain-forensics.hf.space 

done
## Built for - Openenv X meta X pytorch X SST - Hackathon(Round 1)
