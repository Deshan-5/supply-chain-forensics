---
title: Supply Chain Forensics
emoji: 🔍
colorFrom: red
colorTo: orange
sdk: docker
app_file: app.py
pinned: false
---

# Supply Chain Forensics

OpenEnv benchmark. Agent investigates compromised dependencies.

## What

Four scenarios. Agent gets a project with poisoned packages. Has to find which ones and classify the attack type. Scored on precision/recall.

Attack types:
- Typosquat (easy)
- Hijacked maintainer (medium)  
- Transitive poisoning (hard)
- Dependency confusion (confusion)

## Why

npm/PyPI attacks work because scanners only catch known CVEs. New attack patterns slip through. Investigation requires reasoning: correlate publish gaps with maintainer dormancy, trace dependency trees, spot namespace conflicts.

This tests whether an agent can do that investigation.

## How it works

Agent calls actions. Each costs a step.

Actions:
- inspect_package(name)
- check_publish_history(name)
- check_maintainer(name)
- trace_network(build_step)
- get_dependency_tree(depth)
- submit_findings(packages, vectors)

Environment returns observations. Agent submits findings when ready.

Score = F1 on flagged packages + vector classification bonus - step penalty

## Run

```bash
pip install -r requirements.txt
uvicorn app:app --port 7860
```

Agent:
```bash
export HF_TOKEN=key
export MODEL_NAME=claude-sonnet-4-6
python inference.py
```

## Scenarios

Based on real attacks:
- ua-parser-js hijack (Oct 2021, 8M weekly DL)
- event-stream backdoor (Nov 2018)
- SolarWinds build compromise (Dec 2020)

Each scenario includes red herrings. Legitimate packages with minor anomalies mixed in.

## Files

```
app.py                  # FastAPI server
env/environment.py      # Core logic
env/scenarios/*.json    # Attack data
inference.py            # Baseline agent
```

## Expected scores

GPT-4o targets:
- easy: 0.9-1.0
- medium: 0.7-0.9
- hard: 0.3-0.6
- confusion: 0.5-0.8

Hard scenario has 8 packages, 1 malicious, 2 red herrings with install scripts.

