---
title: Supply Chain Forensics
emoji: 🔍
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---

# Supply Chain Forensics

AI agents break the moment security stops being obvious.

This project is a benchmark for testing whether an agent can investigate software supply chain attacks the way a human analyst would: by following weak signals, checking provenance, and making decisions under pressure.

---

## Why this exists

Most modern compromises don’t happen in application code.

They happen in dependencies.

A single malicious package can:
- quietly enter through the dependency graph  
- execute only under specific conditions (CI, install time, etc.)  
- bypass traditional scanners entirely  

This pattern shows up repeatedly in incidents like SolarWinds, Codecov, the XZ backdoor, and recent npm ecosystem compromises.

The attack is rarely obvious.  
The signal is weak.  
Detection requires reasoning.

---

## What this is

Supply Chain Forensics is an OpenEnv environment where an agent investigates a compromised project.

Each episode simulates a realistic supply chain attack using structured signals:

- package manifests  
- dependency graphs  
- publish history  
- maintainer metadata  
- install-time scripts  
- network activity  

The agent must:
1. explore the system  
2. identify anomalies  
3. trace the root cause  
4. submit findings  

All under a fixed step budget.

---

## Scenarios

| Task | Scenario | What the agent must figure out |
|------|----------|-------------------------------|
| easy | Typosquat | a malicious package mimicking a popular one |
| medium | Hijacked maintainer | legitimate package compromised after takeover |
| hard | Transitive poisoning | malicious dependency hidden deep in the graph |
| confusion | Dependency confusion | public package replacing an expected internal one |

These are not synthetic puzzles.  
They reflect real attack patterns seen in production ecosystems.

---

## How the environment works

The agent interacts with a simple API:

POST /reset  
POST /step  
GET  /state/{session_id}  

A typical loop:

observe → act → receive feedback → repeat → submit findings  

---

## Example

A project passes a standard audit with zero vulnerabilities.

The agent still finds:

- a low-download package replacing an internal dependency  
- an install script making outbound network calls  
- behavior triggered only during install  

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

Run the agent:

python3 inference.py  

---

## Design choices

- Behavior over signatures  
- Graph-first reasoning  
- Step constraints simulate real investigation pressure  
- Deterministic scoring  
- LLM-driven agent with fallback  

---

## Bottom line

Security tools detect known issues.

Modern attacks avoid known issues.

Agents need to reason.

This project is a benchmark for that.
