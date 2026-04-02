# Supply Chain Attack Forensics Lab

> An OpenEnv environment where an AI agent investigates compromised software dependencies — built in response to the March 2026 Axios NPM compromise and the broader epidemic of supply chain attacks that cost the industry $60B in 2025.

---

## Overview

Software supply chain attacks have become the most dangerous vector in modern infrastructure security. The 2020 SolarWinds attack compromised 18,000 organizations through a single trojanized build artifact. The 2024 XZ Utils backdoor was planted over two years of social engineering. In March 2026, the Axios NPM package — downloaded 48 million times per week — was compromised via maintainer credential theft.

Despite this, **no agent benchmark exists for supply chain forensics**.

This environment fills that gap. An AI agent receives a realistic software project: package manifests, git history, CI/CD logs, network traces from the build pipeline, and audit outputs. Hidden within the dependencies are real attack patterns. The agent must investigate, reason about anomalies, and identify the compromised package(s) — using a fixed step budget, just like a human analyst under incident response pressure.

---

## Tasks

| Task | Attack Pattern | Difficulty | Max Steps |
|------|---------------|------------|-----------|
| `easy` | Typosquat (`lod-ash` vs `lodash`) | Easy | 12 |
| `medium` | Hijacked maintainer — 17-week gap, IP region change, obfuscated reverse shell | Medium | 20 |
| `hard` | Poisoned transitive dependency, 4 levels deep, CI-triggered only | Hard | 30 |

### Easy: Typosquat Detection
A JavaScript fintech project (`payvault-api`) has a dependency named `lod-ash` — published 3 months ago by a single unknown maintainer, 312 weekly downloads vs lodash's 48M, and a `postinstall` script that beacons the victim's hostname and username to an attacker-controlled server. Standard `npm audit` reports 0 vulnerabilities.

### Medium: Hijacked Maintainer
A Python analytics worker (`edgeflow-worker`) depends on `datastream-utils`, a legitimate package with a 3-year publish history. Version `0.4.3`, released after a 17-week gap, was published from a different IP region (DE→RU). This version introduced a `post_install` hook containing base64-encoded reverse shell code that only activates when CI environment variables are present. The attack pattern mirrors the March 2026 Axios incident.

### Hard: Transitive Dependency Poisoning
A Next.js enterprise platform (`nexus-platform`) has 847 total packages. The malicious package is `async-stat-collector@3.1.6`, buried at:

```
nexus-platform → webpack-bundle-optimizer → build-perf-metrics → async-stat-collector
```

It was introduced via an automated weekly dependency bump. The obfuscated install script reads `~/.ssh/config` and `~/.aws/credentials` and exfiltrates them to a C2 server — but **only in CI environments**. npm audit reports 0 vulnerabilities. A human engineer investigated for 20 minutes and closed the alert as a false positive.

---

## Action Space

| Action | Description |
|--------|-------------|
| `list_packages()` | List all packages in the manifest |
| `get_audit_output()` | Run automated audit (won't catch novel attacks) |
| `get_git_log()` | View recent commits |
| `inspect_package(name)` | View source code, install scripts, metadata |
| `check_publish_history(name)` | Inspect version timeline for anomalies |
| `check_maintainer(name)` | Check account age, dormancy, activity patterns |
| `trace_network(build_step)` | See outbound network requests during build |
| `check_similarity(name, reference)` | Detect typosquatting via edit distance |
| `get_dependency_tree(depth)` | Explore transitive dependencies up to 5 levels |
| `submit_findings(packages, attack_vectors)` | End episode with final verdict |

---

## Observation Space

Each step returns a structured observation:

```json
{
  "step": 4,
  "action_taken": "check_publish_history({\"name\": \"datastream-utils\"})",
  "result": {
    "analysis": "ANOMALIES DETECTED: Publisher IP region changed. 17-week gap since last release.",
    "version_history": [...]
  },
  "packages_flagged": [],
  "steps_remaining": 16,
  "last_action_error": null
}
```

---

## Reward Function

| Signal | Value |
|--------|-------|
| Per step (efficiency penalty) | −0.02 |
| F1 score on flagged packages | × 0.80 |
| Correct attack vector per package | +0.10 |
| Efficiency bonus (solved under optimal steps) | up to +0.10 |
| **Total score range** | **[0.0, 1.0]** |

The per-step penalty mirrors real incident response — an analyst who investigates every single package wastes the company's time and money. The environment rewards focused, hypothesis-driven investigation.

---

## API Reference

### `POST /reset`
```json
{ "task": "easy" }
```
Returns `session_id` and initial observation.

### `POST /step`
```json
{
  "session_id": "easy_a3f2",
  "action": "inspect_package",
  "params": { "name": "lod-ash" }
}
```

### `GET /state/{session_id}`
Returns current episode state without consuming a step.

### `GET /health`
Returns `{"status": "ok"}`. Used for automated uptime checks.

---

## Setup

### Local

```bash
git clone <your-repo-url>
cd supply-chain-forensics
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 7860
```

### Docker

```bash
docker build -t supply-chain-forensics .
docker run -p 7860:7860 supply-chain-forensics
```

### Run the agent

```bash
export HF_TOKEN=your_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export SUPPLY_CHAIN_TASK=hard
export ENV_BASE_URL=http://localhost:7860
python inference.py
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HF_TOKEN` | Yes | Hugging Face / API key |
| `API_BASE_URL` | Yes | LLM endpoint URL |
| `MODEL_NAME` | Yes | Model identifier |
| `SUPPLY_CHAIN_TASK` | No | `easy` / `medium` / `hard` (default: `easy`) |
| `ENV_BASE_URL` | No | Environment server URL (default: `http://localhost:7860`) |

---

## Why This Matters

Every company using open source software — which is every company — is vulnerable to supply chain attacks. Existing defenses are reactive: they detect known CVEs after the fact. What the industry needs is an AI agent that can reason about behavioral anomalies: unexpected publish gaps, maintainer account dormancy, suspicious install scripts, and novel C2 patterns.

This environment provides a benchmark for training and evaluating exactly that capability.

---

## Real-World Attack References

- **SolarWinds (2020)** — trojanized build artifact, 18,000 compromised organizations
- **Codecov (2021)** — CI environment credential theft via bash uploader
- **Log4Shell (2021)** — transitive dependency in 3 billion Java applications  
- **XZ Utils (2024)** — 2-year social engineering campaign to plant a backdoor
- **Axios NPM (March 2026)** — maintainer credential theft, 48M weekly downloads affected
