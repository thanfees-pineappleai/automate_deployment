"""
Simple multi-project GitHub webhook -> deploy runner.

Features
- Multiple endpoints: /hook/{project}
- Per-project secret (HMAC SHA-256) verification with X-Hub-Signature-256
- Filters by repo and branch (optional)
- Runs your existing .sh deploy scripts asynchronously
- Health endpoint at /health

Run
  python3 automate.py --host 127.0.0.1 --port 9000

Configure
- Set env var WEBHOOK_CONFIG to a JSON file path (recommended: /etc/webhook-deploy.json).
- Or place webhook-config.json next to this script.

Example /etc/webhook-deploy.json
{
  "shared": { "exec_timeout_sec": 1800, "log_level": "INFO" },
  "projects": {
    "proj1": {
      "secret_env": "GITHUB_SECRET_PROJ1",
      "script": "/opt/deploy/proj1_deploy.sh",
      "repo": "org/repo1",
      "branches": ["refs/heads/main"],
      "workdir": "/var/www/proj1"
    },
    "proj2": {
      "secret_env": "GITHUB_SECRET_PROJ2",
      "script": "/opt/deploy/proj2_deploy.sh",
      "repo": "org/repo2",
      "branches": ["refs/heads/master"]
    }
  }
}
Set the env vars (e.g. in systemd) and ensure scripts are executable.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import subprocess
import sys
import threading
from collections import deque
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    import uvicorn
except Exception as exc:  # pragma: no cover - import-time guidance
    print(
        "Missing dependencies. Install with: pip install fastapi uvicorn",
        file=sys.stderr,
    )
    raise


# ----------------------------- Config loading -----------------------------

DEFAULT_CONFIG_FILE = "webhook-config.json"


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_config() -> Dict[str, Any]:
    cfg_path = os.environ.get("WEBHOOK_CONFIG")
    if cfg_path:
        p = Path(cfg_path)
        if not p.exists():
            raise FileNotFoundError(f"WEBHOOK_CONFIG file not found: {p}")
        config = _read_json(p)
    else:
        p = Path(__file__).with_name(DEFAULT_CONFIG_FILE)
        config = _read_json(p) if p.exists() else {"projects": {}, "shared": {}}

    if "projects" not in config:
        config["projects"] = {}
    if "shared" not in config:
        config["shared"] = {}
    return config


# ----------------------------- App + Globals -----------------------------

app = FastAPI(title="GitHub Webhook Deploy", version="1.0")

CONFIG: Dict[str, Any] = {}
PROJECTS: Dict[str, Any] = {}
PROJECT_LOCKS: Dict[str, threading.Lock] = {}
RECENT_DELIVERIES: deque[str] = deque(maxlen=2000)


def configure_logging(level_str: str) -> None:
    level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def init_state() -> None:
    global CONFIG, PROJECTS, PROJECT_LOCKS
    CONFIG = load_config()
    configure_logging(CONFIG.get("shared", {}).get("log_level", "INFO"))
    PROJECTS = CONFIG.get("projects", {})
    PROJECT_LOCKS = {slug: threading.Lock() for slug in PROJECTS.keys()}
    logging.info("Loaded %d project configs", len(PROJECTS))


@app.on_event("startup")
async def _startup() -> None:
    init_state()


# ----------------------------- Utilities ---------------------------------

def get_project(slug: str) -> Optional[Dict[str, Any]]:
    return deepcopy(PROJECTS.get(slug))


def get_secret(proj_cfg: Dict[str, Any]) -> Optional[bytes]:
    secret_env = proj_cfg.get("secret_env")
    if secret_env:
        v = os.environ.get(secret_env)
        if v:
            return v.encode("utf-8")
    if proj_cfg.get("secret"):
        return str(proj_cfg["secret"]).encode("utf-8")
    return None


def verify_github_signature(secret: bytes, signature_256: str, body: bytes) -> bool:
    if not signature_256 or not signature_256.startswith("sha256="):
        return False
    sent_sig = signature_256.split("=", 1)[1]
    mac = hmac.new(secret, msg=body, digestmod=hashlib.sha256)
    expected = mac.hexdigest()
    return hmac.compare_digest(expected, sent_sig)


def branch_from_ref(ref: str) -> str:
    # e.g. refs/heads/main -> main
    if not ref:
        return ""
    parts = ref.split("/", 2)
    return parts[-1] if len(parts) >= 3 else ref


def _run_script(script: str, env: Dict[str, str], workdir: Optional[str], timeout: int) -> int:
    logger = logging.getLogger("runner")
    cmd = ["/bin/bash", script]
    logger.info("Starting script: %s (cwd=%s)", script, workdir or os.getcwd())
    try:
        res = subprocess.run(
            cmd,
            cwd=workdir or None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        for line in res.stdout.splitlines():
            logger.info("[script] %s", line)
        logger.info("Script finished with code %s", res.returncode)
        return res.returncode
    except subprocess.TimeoutExpired:
        logger.error("Script timed out after %ss", timeout)
        return 124
    except FileNotFoundError:
        logger.exception("Script not found or not executable: %s", script)
        return 127
    except Exception:  # pragma: no cover - defensive
        logger.exception("Script failed unexpectedly")
        return 1


async def launch_deploy(slug: str, proj_cfg: Dict[str, Any], payload: Dict[str, Any], headers: Dict[str, str]) -> None:
    lock = PROJECT_LOCKS.setdefault(slug, threading.Lock())
    if lock.locked():
        logging.warning("Project %s deploy already running; triggering another may overlap", slug)

    repo = payload.get("repository", {}) or {}
    ref = payload.get("ref", "")
    branch = branch_from_ref(ref)
    head = payload.get("after", "")
    delivery = headers.get("X-GitHub-Delivery", "")
    clone_url = repo.get("ssh_url") or repo.get("clone_url") or ""

    env = os.environ.copy()
    env.update(
        {
            "PROJECT_SLUG": slug,
            "EVENT": headers.get("X-GitHub-Event", ""),
            "DELIVERY_GUID": delivery,
            "GIT_REPO": repo.get("full_name", ""),
            "GIT_URL": clone_url,
            "GIT_REF": ref,
            "GIT_BRANCH": branch,
            "GIT_COMMIT": head,
        }
    )

    # Execute in a thread to avoid blocking the event loop
    timeout = int(CONFIG.get("shared", {}).get("exec_timeout_sec", 3600))
    script = proj_cfg.get("script")
    workdir = proj_cfg.get("workdir")

    def _target():
        with lock:
            _run_script(script, env, workdir, timeout)

    thread = threading.Thread(target=_target, name=f"deploy-{slug}", daemon=True)
    thread.start()


# ----------------------------- Routes -------------------------------------


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": True})


@app.post("/hook/{slug}")
async def hook(slug: str, request: Request) -> JSONResponse:
    proj = get_project(slug)
    if not proj:
        raise HTTPException(status_code=404, detail="Unknown project slug")

    body = await request.body()
    headers = {k: v for k, v in request.headers.items()}
    event = headers.get("X-GitHub-Event", "")
    delivery_id = headers.get("X-GitHub-Delivery", "")
    content_type = headers.get("content-type", "")

    if not content_type.startswith("application/json"):
        raise HTTPException(status_code=415, detail="Unsupported content type")

    # Replay protection (best-effort, in-memory)
    if delivery_id and delivery_id in RECENT_DELIVERIES:
        return JSONResponse({"status": "duplicate", "delivery_id": delivery_id}, status_code=202)

    secret = get_secret(proj)
    if not secret:
        logging.error("Project '%s' has no secret configured", slug)
        raise HTTPException(status_code=500, detail="Project not configured with secret")

    signature_256 = headers.get("X-Hub-Signature-256", "")
    if not verify_github_signature(secret, signature_256, body):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Accept ping for connectivity check
    if event == "ping":
        RECENT_DELIVERIES.append(delivery_id)
        return JSONResponse({"status": "pong", "delivery_id": delivery_id})

    if event != "push":
        return JSONResponse({"status": "ignored", "event": event}, status_code=202)

    repo_full = payload.get("repository", {}).get("full_name")
    ref = payload.get("ref")

    if proj.get("repo") and proj["repo"] != repo_full:
        raise HTTPException(status_code=400, detail="Repository mismatch")

    branches = proj.get("branches") or []
    if branches and ref not in branches:
        # Allow refs/heads/<branch> in config or plain branch names
        allowed = set(branches)
        allowed |= {f"refs/heads/{b}" for b in branches}
        if ref not in allowed:
            return JSONResponse(
                {"status": "ignored", "reason": "branch filtered", "ref": ref},
                status_code=202,
            )

    RECENT_DELIVERIES.append(delivery_id)
    asyncio.create_task(launch_deploy(slug, proj, payload, headers))
    return JSONResponse({"status": "accepted", "delivery_id": delivery_id})


# ----------------------------- Entrypoint ---------------------------------


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="GitHub webhook deploy server")
    p.add_argument("--host", default="127.0.0.1", help="Bind host")
    p.add_argument("--port", type=int, default=9000, help="Bind port")
    p.add_argument(
        "--reload", action="store_true", help="Enable auto-reload (dev only)"
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    # Ensure state is initialized if running outside FastAPI lifecycle (e.g. uvicorn import)
    if not PROJECTS:
        init_state()
    uvicorn.run(
        "automate:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=(CONFIG.get("shared", {}).get("log_level", "info").lower()),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
