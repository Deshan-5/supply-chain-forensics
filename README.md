---

title: Supply Chain Forensics
emoji: 🔍
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
-------------

# Supply Chain Attack Forensics Lab

> A benchmark for training AI agents to detect software supply chain attacks.
> Built for OpenEnv Hackathon — Meta × Hugging Face × PyTorch

---

## Why this exists

Most systems today don’t get compromised through application code.

They get compromised through dependencies.

We have tools for known vulnerabilities.
We don’t have tools for reasoning about unknown ones.

AI agents today fail here.

---

## What this is

An OpenEnv environment where an agent investigates a compromised software project.

Each episode gives the agent:

* dependency manifests
* package graphs
* git history
* maintainer metadata
* CI/CD traces
* network logs

The agent explores, identifies anomalies, and submits findings — under a fixed step budget.

---

## Tasks

| Task   | Scenario                         |
| ------ | -------------------------------- |
| easy   | Typosquatted package (`lod-ash`) |
| medium | Hijacked maintainer              |
| hard   | Transitive dependency poisoning  |

These are based on real attack patterns, not synthetic ones.

---

## Example

```bash
POST /reset → task=hard
```

```json
{
  "packages": ["next", "react", "webpack-bundle-optimizer", "axios"]
}
```

```bash
get_dependency_tree(depth=4)
```

```
nexus-platform
  → webpack-bundle-optimizer
    → build-perf-metrics
      → async-stat-collector
```

```bash
inspect_package("async-stat-collector")
```

Findings:

* suspicious install script
* reads local credentials
* triggers only in CI

```bash
submit_findings(...)
```

---

## API

```
POST /reset
POST /step
GET  /state/{session_id}
GET  /health
```

---

## How it works

```
Agent (inference.py)
        ↓
FastAPI server
        ↓
Environment core
        ↓
Scenario engine
        ↓
Grader
```

---

## Scoring

* small penalty per step
* reward for correct packages
* reward for correct attack classification
* bonus for efficiency

Final score ∈ [0, 1]

---

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 7860
```

```bash
python inference.py
```

---

## Docker

```bash
docker build -t supply-chain-forensics .
docker run -p 7860:7860 supply-chain-forensics
```

---

## What this enables

* training agents for incident response
* testing reasoning over dependency graphs
* evaluating detection of novel supply chain attacks

---

## References

SolarWinds (2020)
Codecov (2021)
Log4Shell (2021)
XZ Utils (2024)
Axios NPM compromise (2026)
