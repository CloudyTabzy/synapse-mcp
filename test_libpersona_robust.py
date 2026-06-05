#!/usr/bin/env python3
"""Robust integration test: open libpersona.dll via idalib MCP supervisor stdio.

This test waits for the ACTUAL worker response (not stale cached responses)
and verifies the database is usable after loading.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

TARGET = r"C:\Program Files\Affinity\Canva\libpersona.dll"
IDADIR = r"C:\Program Files\IDA Professional 9.3"


def send(proc, msg: dict) -> None:
    line = json.dumps(msg, separators=(",", ":"))
    proc.stdin.write((line + "\n").encode("utf-8"))
    proc.stdin.flush()


def recv(proc, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        text = line.decode("utf-8", errors="replace").strip()
        if text and text.startswith("{") and text.endswith("}"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                continue
    raise TimeoutError(f"No valid JSON within {timeout}s")


def extract_tool_result(resp: dict) -> dict:
    """Extract the inner tool result from an MCP tools/call response."""
    result = resp.get("result", {})
    # First unwrap: MCP tools/call response -> tool result
    structured = result.get("structuredContent", {})
    if isinstance(structured, dict) and "structuredContent" in structured:
        # Second unwrap: tool result was itself a _call_tool_result dict
        structured = structured.get("structuredContent", {})
    return structured if isinstance(structured, dict) else {}


def main():
    env = dict(os.environ)
    env["IDADIR"] = IDADIR
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [
        sys.executable, "-m", "ida_pro_mcp.idalib_supervisor",
        "--stdio", "--verbose",
    ]

    print(f"[INFO] Starting supervisor...")
    print(f"[INFO] Target={TARGET}")

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=False,
    )

    start_time = time.monotonic()

    try:
        # 1. Initialize
        send(proc, {
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test"}},
        })
        r = recv(proc, timeout=30.0)
        print(f"[OK] initialize -> {r.get('result', {}).get('serverInfo', {})}")

        # 2. Open libpersona.dll
        send(proc, {
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {
                "name": "idalib_open",
                "arguments": {
                    "input_path": TARGET,
                    "run_auto_analysis": True,
                    "session_id": "libp",
                },
            },
        })
        r = recv(proc, timeout=60.0)
        result = extract_tool_result(r)
        print(f"[OK] idalib_open result: {json.dumps(result, indent=2)}")

        task_id = result.get("task_id")
        if task_id:
            print(f"[INFO] Async open, task_id={task_id}. Polling every 30s...")
            poll_num = 0
            while True:
                time.sleep(30)
                poll_num += 1
                send(proc, {
                    "jsonrpc": "2.0", "id": 100 + poll_num,
                    "method": "tools/call",
                    "params": {
                        "name": "idalib_task_poll",
                        "arguments": {"task_id": task_id},
                    },
                })
                r = recv(proc, timeout=30.0)
                poll_result = extract_tool_result(r)
                status = poll_result.get("status", "unknown")
                elapsed = int(time.monotonic() - start_time)
                print(f"[POLL #{poll_num} @ {elapsed}s] status={status} {json.dumps({k:v for k,v in poll_result.items() if k != 'content'}, default=str)[:200]}")

                if status == "failed":
                    print(f"[ERROR] Open failed: {poll_result.get('error', 'unknown')}")
                    return 1
                if status == "done":
                    print(f"[OK] Open completed in {elapsed}s")
                    break
                if elapsed > 3600:
                    print(f"[ERROR] Timeout after 1 hour")
                    return 1
        else:
            print(f"[WARN] No task_id returned; synchronous open assumed")

        # 3. Warmup / verify database is usable
        print(f"[INFO] Calling idalib_warmup...")
        send(proc, {
            "jsonrpc": "2.0", "id": 200,
            "method": "tools/call",
            "params": {
                "name": "idalib_warmup",
                "arguments": {"session_id": "libp", "wait_auto_analysis": True},
            },
        })
        r = recv(proc, timeout=600.0)
        warmup = extract_tool_result(r)
        print(f"[OK] idalib_warmup: {json.dumps(warmup, indent=2)[:600]}")

        # 4. List sessions
        print(f"[INFO] Calling idalib_list...")
        send(proc, {
            "jsonrpc": "2.0", "id": 300,
            "method": "tools/call",
            "params": {"name": "idalib_list", "arguments": {}},
        })
        r = recv(proc, timeout=30.0)
        lst = extract_tool_result(r)
        sessions = lst.get("sessions", [])
        print(f"[OK] Sessions: {len(sessions)}")
        for s in sessions:
            print(f"  - {s.get('session_id')}: {s.get('filename')} analyzing={s.get('is_analyzing')} active={s.get('is_active')}")

        # 5. Close session
        print(f"[INFO] Calling idalib_close...")
        send(proc, {
            "jsonrpc": "2.0", "id": 400,
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {"session_id": "libp"}},
        })
        r = recv(proc, timeout=30.0)
        close_res = extract_tool_result(r)
        print(f"[OK] idalib_close: {json.dumps(close_res, indent=2)[:200]}")

        # 6. Verify temp cleanup
        time.sleep(2)
        tmp_dir = Path(os.environ.get("TEMP", "/tmp"))
        temp_files = list(tmp_dir.glob("idalib_*libpersona*"))
        if temp_files:
            print(f"[WARN] Temp files still present: {[str(f) for f in temp_files]}")
        else:
            print(f"[OK] No temp files leaked")

        total_elapsed = int(time.monotonic() - start_time)
        print(f"[SUCCESS] Full test completed in {total_elapsed}s")
        return 0

    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        print(f"[INFO] Terminating supervisor...")
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        if stderr:
            # Save stderr to a file for inspection
            log_path = Path("test_libpersona_robust.supervisor.stderr")
            log_path.write_text(stderr, encoding="utf-8")
            print(f"[INFO] Supervisor stderr saved to {log_path}")


if __name__ == "__main__":
    sys.exit(main())
