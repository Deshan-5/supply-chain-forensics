"""
Supply Chain Forensics — FastAPI Server
=======================================
OpenEnv-compliant HTTP API. Deployed to Hugging Face Spaces.
"""

import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from env.environment import ActionRequest, SupplyChainEnv

app = FastAPI(
    title="Supply Chain Attack Forensics Lab",
    description=(
        "OpenEnv environment where an AI agent investigates compromised software "
        "dependencies. Simulates real-world supply chain attacks: typosquats, "
        "hijacked maintainer accounts, and poisoned transitive dependencies."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (single-user for benchmark runs)
_sessions: dict[str, SupplyChainEnv] = {}


# ─── Request/Response Models ─────────────────────────────────────────────────

class ResetRequest(BaseModel):
    task: Optional[str] = "easy"  # easy | medium | hard


class StepRequest(BaseModel):
    session_id: str
    action: str
    params: dict[str, Any] = {}


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "env": "supply-chain-forensics"}


@app.get("/")
def root():
    return {
        "name": "Supply Chain Attack Forensics Lab",
        "version": "1.0.0",
        "tasks": ["easy", "medium", "hard", "confusion"],
        "endpoints": {
            "reset": "POST /reset",
            "step":  "POST /step",
            "state": "GET  /state/{session_id}",
        }
    }


@app.post("/reset")
def reset(req: ResetRequest):
    """
    Start a new episode.
    Returns session_id and initial observation (briefing + package manifest).
    """
    difficulty = req.task or "easy"
    if difficulty not in ("easy", "medium", "hard", "confusion"):
        raise HTTPException(400, f"task must be 'easy', 'medium', 'hard', or 'confusion'. Got: '{difficulty}'")

    session_id = f"{difficulty}_{os.urandom(4).hex()}"
    env = SupplyChainEnv(difficulty=difficulty)
    result = env.reset()
    _sessions[session_id] = env

    return {
        "session_id": session_id,
        "task": difficulty,
        "observation": result.observation.model_dump(),
        "reward": result.reward,
        "done": result.done,
    }


@app.post("/step")
def step(req: StepRequest):
    """
    Execute one investigative action.
    Returns updated observation, reward, and done flag.
    """
    env = _sessions.get(req.session_id)
    if env is None:
        raise HTTPException(404, f"Session '{req.session_id}' not found. Call /reset first.")

    action_request = ActionRequest(action=req.action, params=req.params)
    result = env.step(action_request)

    return {
        "session_id": req.session_id,
        "observation": result.observation.model_dump(),
        "reward": result.reward,
        "done": result.done,
        "info": result.info,
    }


@app.get("/state/{session_id}")
def state(session_id: str):
    """Return current environment state without consuming a step."""
    env = _sessions.get(session_id)
    if env is None:
        raise HTTPException(404, f"Session '{session_id}' not found.")
    return env.state().model_dump()


@app.get("/tasks")
def list_tasks():
    """List available tasks with descriptions."""
    return {
        "tasks": [
            {
                "id": "easy",
                "name": "Typosquat Detection",
                "description": "Identify an obvious typosquatted package in a JavaScript project.",
                "difficulty": "easy",
                "max_steps": 12,
                "hints": "Look for packages with unusual download counts or unfamiliar author names."
            },
            {
                "id": "medium",
                "name": "Hijacked Maintainer",
                "description": (
                    "A legitimate package was compromised after the maintainer's credentials were stolen. "
                    "The attack mirrors the March 2026 Axios NPM incident."
                ),
                "difficulty": "medium",
                "max_steps": 20,
                "hints": "Check version publish history. Look for unexpected gaps or IP region changes."
            },
            {
                "id": "hard",
                "name": "Transitive Dependency Poisoning",
                "description": (
                    "A malicious package is buried 4 levels deep in the dependency tree. "
                    "It only activates in CI environments and won't appear in audit scans."
                ),
                "difficulty": "hard",
                "max_steps": 30,
                "hints": "Direct deps look clean. Trace network logs. Explore the full dependency tree."
            },
            {
                "id": "confusion",
                "name": "Dependency Confusion",
                "description": (
                "A public package shadows an expected internal dependency and executes "
                "unexpected install-time behavior."
                ),
                "difficulty": "medium",
                "max_steps": 20,
                "hints": "Compare expected internal package naming with what was actually installed."
            }
            
        ]
    }

