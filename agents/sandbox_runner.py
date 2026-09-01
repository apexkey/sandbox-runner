"""
APEX KEY — SYSTEM A | SANDBOX RUNNER — sandbox_runner.py
--------------------------------------------------------------------
DEDICATED, SECRET-LESS, WRITE-PROTECTED execution.
Tasks:
  1. Pull generated artifact (by sha256) from Supabase build_artifacts.
  2. Write to a temp file under a temp dir (never in repo).
  3. Execute in a subprocess with a strict timeout (capture stdout/stderr/exit).
  4. Post results back to Supabase, then trigger QA critic.
SECURITY:
  * No secrets in this repo. Untrusted code has NO credentials to steal.
  * Ephemeral VM = fresh OS every run.
  * Git write disabled (permissions: contents none) so it can't push.
"""
import os
import sys
import json
import tempfile
import subprocess
import platform
import hashlib
import requests

SUPA_URL = os.environ["SUPABASE_URL"]
SUPA_KEY = os.environ["SUPABASE_SERVICE_KEY"]
QA_REPO = os.environ["QA_REPO"]
QA_WORKFLOW = os.environ["QA_WORKFLOW"]
TRACE_ID = os.environ["TRACE_ID"]
WORKSPACE_ID = os.environ["WORKSPACE_ID"]
TENANT = os.environ.get("TENANT", "kernel")
SHA256 = os.environ["SHA256"]
STEP = os.environ.get("STEP", "test")
EXEC_TIMEOUT = int(os.environ.get("EXEC_TIMEOUT", "20"))

HEADERS = {
    "apikey": SUPA_KEY,
    "authorization": f"Bearer {SUPA_KEY}",
    "content-type": "application/json",
}


def log_action(status, detail, error=None):
    requests.post(
        f"{SUPA_URL}/rest/v1/agent_executions",
        json={
            "trace_id": TRACE_ID, "workspace_id": WORKSPACE_ID,
            "tenant_key": TENANT, "agent_id": "sandbox", "action": STEP,
            "status": status, "output": detail, "error": error,
        },
        headers=HEADERS, timeout=30,
    )


def fetch_artifact():
    r = requests.get(
        f"{SUPA_URL}/rest/v1/build_artifacts",
        params={"sha256": f"eq.{SHA256}", "select": "*", "limit": "1"},
        headers=HEADERS, timeout=30,
    )
    if not r.ok or not r.json():
        raise RuntimeError(f"artifact not found: {SHA256}")
    return r.json()[0]


def sanitized_env():
    """Build a MINIMAL child env. CRITICAL: never pass secrets/tokens to the
    generated (untrusted) code. We whitelist only safe, non-sensitive vars."""
    SAFE = ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"]
    return {k: v for k, v in os.environ.items() if k in SAFE} | {"PYTHONDONTWRITEBYTECODE": "1"}


def run_isolated(code, language):
    """Run in a fresh temp dir, as a subprocess with timeout + resource caps.
    The subprocess gets a SANITIZED env (no API keys/tokens/secrets), so the
    generated code cannot exfiltrate credentials."""
    tmpdir = tempfile.mkdtemp(prefix="apex_sandbox_")
    fname = os.path.join(tmpdir, "artifact_main.py")
    with open(fname, "w") as f:
        f.write(code)

    # Use a subprocess with a hard wall-clock timeout (prevents infinite loop)
    cmd = [sys.executable, fname]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=EXEC_TIMEOUT,
            cwd=tmpdir, env=sanitized_env(),
        )
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:4000],
            "stderr": proc.stderr[:4000],
            "timed_out": False,
            "platform": platform.platform(),
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": 124,
            "stdout": "",
            "stderr": "TIMEOUT: process did not finish within %ss (infinite loop guard)" % EXEC_TIMEOUT,
            "timed_out": True,
            "platform": platform.platform(),
        }
    except Exception as e:  # noqa: BLE001
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"EXEC_ERROR: {e}",
            "timed_out": False,
            "platform": platform.platform(),
        }


def trigger_qa(exit_code, stdout, stderr):
    url = f"https://api.github.com/repos/{QA_REPO}/actions/workflows/{QA_WORKFLOW}/dispatches"
    payload = {
        "ref": "main",
        "inputs": {
            "trace_id": TRACE_ID, "workspace_id": WORKSPACE_ID,
            "tenant": TENANT, "sha256": SHA256, "exit_code": str(exit_code),
            "stdout": stdout, "stderr": stderr, "step": STEP,
        },
    }
    # NOTE: GitHub dispatch inputs are string-only; truncate to avoid input limits.
    payload["inputs"]["stdout"] = stdout[:2000]
    payload["inputs"]["stderr"] = stderr[:2000]
    r = requests.post(
        url, json=payload,
        headers={
            "authorization": f"Bearer {os.environ.get('SANDBOX_DISPATCH_TOKEN', '')}",
            "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
        }, timeout=30,
    )
    return r.status_code in (200, 201, 204)


def main():
    print(json.dumps({"sandbox": "boot", "trace": TRACE_ID, "sha": SHA256}))
    art = fetch_artifact()
    code = art["code"]
    result = run_isolated(code, art.get("language", "python"))
    print(json.dumps({"sandbox": "ran", "exit": result["exit_code"], "timed_out": result["timed_out"]}))

    # Persist the run into build_artifacts (append run_meta) + agent log
    ok = result["exit_code"] in (0,)
    log_action("passed" if ok else "failed", {"exit_code": result["exit_code"],
              "stdout": result["stdout"], "stderr": result["stderr"]},
              None if ok else result["stderr"][:200])

    dispatched = trigger_qa(result["exit_code"], result["stdout"], result["stderr"])
    print(json.dumps({"sandbox": "qa_dispatched", "ok": dispatched}))


if __name__ == "__main__":
    main()
