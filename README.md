<!--
title: Supply Chain Forensics
emoji: 🔍
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
-->

# Supply Chain Forensics

AI agents are not ready for real-world security.

This project is a benchmark to change that.

---

## The problem

Modern systems don’t get hacked at the application layer.

They get hacked through dependencies.

- A single compromised package can impact thousands of apps  
- Most attacks don’t trigger CVEs  
- Malicious behavior is often hidden, delayed, or environment-specific  

This pattern shows up repeatedly:

- SolarWinds (2020) — build pipeline compromise  
- Codecov (2021) — CI environment exfiltration  
- XZ Utils (2024) — maintainer-level backdoor  
- Axios NPM incident (2026) — package ecosystem compromise  

The attack is not obvious.  
The signal is buried.  
Detection requires reasoning.

---

## What this is

Supply Chain Forensics is an OpenEnv environment where an agent investigates a compromised codebase.

Each episode simulates a real supply chain attack using:

- package manifests  
- dependency graphs  
- publish history  
- maintainer metadata  
- install-time behavior  
- network activity  

The agent must:

1. explore the system  
2. identify anomalies  
3. trace the root cause  
4. submit findings  

All under a strict step budget.

---

## Why this matters

Security tooling is optimized for known vulnerabilities.

Attackers don’t use known vulnerabilities.

They exploit trust:
- package registries  
- maintainers  
- dependency graphs  

That makes detection a reasoning problem, not a lookup problem.

This benchmark is designed to evaluate that gap.

---

## Scenarios

| Task | Scenario | Signal |
|------|----------|--------|
| easy | Typosquat | name similarity + install behavior |
| medium | Hijacked maintainer | publish anomaly + maintainer change |
| hard | Transitive poisoning | deep dependency + CI-triggered behavior |
| confusion | Dependency confusion | internal vs public package mismatch |

Each scenario maps to real-world attack classes seen in modern ecosystems.

---

## How it works

Agent → API → Environment → Scenario → Reward

POST /reset  
POST /step  
GET /state/{session_id}  

Observations are structured.  
Evaluation is deterministic.  
Scores are reproducible.

---

## Example

A standard audit reports zero vulnerabilities.

The agent still finds:

- a low-download package replacing an internal dependency  
- an install script triggering outbound network calls  
- behavior only active during install  

Final output:

{
  "packages": ["company-utils"],
  "attack_vectors": {
    "company-utils": "dependency_confusion"
  }
}

---

## Running locally

pip install -r requirements.txt  
python3 -m uvicorn app:app --port 7860  

Run agent:

python3 inference.py  

---

## Design

- behavior > signatures  
- graph-first reasoning  
- step constraints simulate real investigation pressure  
- deterministic reward for consistent evaluation  
- LLM-driven agent with fallback for stability  

---

## Bottom line

Security tools detect known issues.

Modern attacks avoid known issues.

Agents need to reason.

This is a benchmark for that.
