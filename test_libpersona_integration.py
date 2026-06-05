#!/usr/bin/env python3
"""Integration test: open libpersona.dll via idalib MCP supervisor stdio."""

import json
import os
import subprocess
import sys
import time

TARGET = r"C:\Program Files\Affinity\Canva\libpersona.dll"
IDADIR = r"C:\Program Files\IDA Professional 9.3"


def send(proc, msg: dict) -> None:
    line = json.dumps(msg, separators=(",", ":"))
    proc.stdin.write((line + "\n").encode("utf-8"))
    proc.stdin.flush()
    print(f"[SEND] {line[:200]}", file=sys.stderr)


def recv(proc, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    collected = ""
    while time.monotonic() < deadline:
        try:
            line = proc.stdout.readline()
        except Exception as e:
            raise RuntimeError(f"stdout read error: {e}")
        if not line:
            time.sleep(0.1)
            continue
        text = line.decode("utf-8", errors="replace")
        collected += text
        stripped = collected.strip()
        if stripped and stripped.startswith("{") and stripped.endswith("}"):
            try:
                result = json.loads(stripped)
                print(f"[RECV] {stripped[:400]}", file=sys.stderr)
                return result
            except json.JSONDecodeError:
                continue
    raise TimeoutError(f"No valid JSON within {timeout}s")


def main():
    env = dict(os.environ)
    env["IDADIR"] = IDADIR
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [
        sys.executable, "-m", "ida_pro_mcp.idalib_supervisor",
        "--stdio", "--verbose",
    ]

    print(f"[INFO] Starting supervisor: {' '.join(cmd)}", file=sys.stderr)
    print(f"[INFO] IDADIR={IDADIR}", file=sys.stderr)
    print(f"[INFO] Target={TARGET}", file=sys.stderr)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=False,
    )

    try:
        # 1. Initialize
        send(proc, {
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test"}},
        })
        r = recv(proc, timeout=30.0)
        print(f"[OK] initialize -> {r.get('result', {}).get('serverInfo', {})}", file=sys.stderr)

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
        r = recv(proc, timeout=900.0)  # wait for open response (could be async)
        content = r.get("result", {}).get("content", [])
        text = content[0].get("text", "{}") if content else "{}"
        result = json.loads(text)
        print(f"[OK] idalib_open result: {json.dumps(result, indent=2)}", file=sys.stderr)

        task_id = result.get("task_id")
        if task_id:
            # Async open — poll
            print(f"[INFO] Async open, task_id={task_id}. Polling...", file=sys.stderr)
            for i in range(120):  # up to ~20 min of polling
                time.sleep(10)
                send(proc, {
                    "jsonrpc": "2.0", "id": 100 + i,
                    "method": "tools/call",
                    "params": {
                        "name": "idalib_task_poll",
                        "arguments": {"task_id": task_id},
                    },
                })
                r = recv(proc, timeout=30.0)
                content = r.get("result", {}).get("content", [])
                text = content[0].get("text", "{}") if content else "{}"
                poll = json.loads(text)
                # Handle double-wrapped _call_tool_result
                if "structuredContent" in poll:
                    poll = poll.get("structuredContent", {})
                status = poll.get("status", "unknown")
                print(f"[POLL #{i}] status={status} full={json.dumps(poll)[:300]}", file=sys.stderr)
                if status in ("done", "failed"):
                    print(f"[FINAL] {json.dumps(poll, indent=2)}", file=sys.stderr)
                    break
            else:
                print("[ERROR] Polling timed out after 120 iterations", file=sys.stderr)

        # 3. List sessions
        send(proc, {
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"name": "idalib_list", "arguments": {}},
        })
        r = recv(proc, timeout=30.0)
        content = r.get("result", {}).get("content", [])
        text = content[0].get("text", "{}") if content else "{}"
        print(f"[OK] idalib_list: {text[:800]}", file=sys.stderr)

    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        if stderr:
            print(f"[STDERR] {stderr[:4000]}", file=sys.stderr)


if __name__ == "__main__":
    main()
