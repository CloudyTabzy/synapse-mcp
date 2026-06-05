#!/usr/bin/env python3
"""HTTP-mode integration test for large binary loading."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

TARGET = r"C:\Program Files\Affinity\Canva\libpersona.dll"
IDADIR = r"C:\Program Files\IDA Professional 9.3"
PORT = 9876


def rpc(payload: dict) -> dict:
    import urllib.request
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/mcp",
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    env = dict(os.environ)
    env["IDADIR"] = IDADIR
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [
        sys.executable, "-m", "ida_pro_mcp.idalib_supervisor",
        "--host", "127.0.0.1", "--port", str(PORT), "--verbose",
    ]

    log_file = open("test_libpersona_http.log", "w", encoding="utf-8")
    sup_stdout = open("test_libpersona_http_sup_stdout.log", "w", encoding="utf-8")
    sup_stderr = open("test_libpersona_http_sup_stderr.log", "w", encoding="utf-8")
    def log(msg: str):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()
        os.fsync(log_file.fileno())

    log("[INFO] Starting supervisor on HTTP port {}...".format(PORT))
    proc = subprocess.Popen(cmd, env=env, stdout=sup_stdout, stderr=sup_stderr)

    # Wait for HTTP server to come up
    for i in range(30):
        try:
            r = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test"}}})
            if "result" in r:
                break
        except Exception:
            pass
        time.sleep(1)
    else:
        log("[ERROR] Supervisor did not start")
        return 1

    log("[OK] initialize -> {}".format(r.get("result", {}).get("serverInfo")))

    start_time = time.monotonic()

    # Open libpersona.dll
    r = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "idalib_open",
                        "arguments": {"input_path": TARGET, "run_auto_analysis": True, "session_id": "libp"}}})
    result = r.get("result", {})
    content = result.get("content", [{}])[0].get("text", "{}")
    open_res = json.loads(content)
    log("[OK] idalib_open: {}".format(json.dumps(open_res, indent=2)))

    task_id = open_res.get("task_id")
    if not task_id:
        log("[WARN] No task_id")
        return 0

    log("[INFO] Polling task {} every 30s...".format(task_id))
    poll_num = 0
    while True:
        time.sleep(30)
        poll_num += 1
        elapsed = int(time.monotonic() - start_time)
        try:
            r = rpc({"jsonrpc": "2.0", "id": 100 + poll_num, "method": "tools/call",
                     "params": {"name": "idalib_task_poll", "arguments": {"task_id": task_id}}})
            result = r.get("result", {})
            content = result.get("content", [{}])[0].get("text", "{}")
            poll_res = json.loads(content)
            # Handle double wrapping
            if "structuredContent" in poll_res:
                poll_res = poll_res.get("structuredContent", {})
            status = poll_res.get("status", "unknown")
            log("[POLL #{} @ {}s] status={}".format(poll_num, elapsed, status))
            if status == "failed":
                log("[ERROR] Open failed: {}".format(poll_res.get("error")))
                return 1
            if status == "done":
                log("[OK] Open completed in {}s".format(elapsed))
                break
            if elapsed > 3600:
                log("[ERROR] Timeout after 1 hour")
                return 1
        except Exception as e:
            log("[ERROR] Poll #{} failed: {}".format(poll_num, e))

    # Warmup
    log("[INFO] Calling idalib_warmup...")
    try:
        r = rpc({"jsonrpc": "2.0", "id": 200, "method": "tools/call",
                 "params": {"name": "idalib_warmup", "arguments": {"session_id": "libp", "wait_auto_analysis": True}}})
        result = r.get("result", {})
        content = result.get("content", [{}])[0].get("text", "{}")
        warmup = json.loads(content)
        if "structuredContent" in warmup:
            warmup = warmup.get("structuredContent", {})
        log("[OK] Warmup: {}".format(json.dumps(warmup, indent=2)[:600]))
    except Exception as e:
        log("[ERROR] Warmup failed: {}".format(e))

    # List sessions
    log("[INFO] Calling idalib_list...")
    try:
        r = rpc({"jsonrpc": "2.0", "id": 300, "method": "tools/call",
                 "params": {"name": "idalib_list", "arguments": {}}})
        result = r.get("result", {})
        content = result.get("content", [{}])[0].get("text", "{}")
        lst = json.loads(content)
        if "structuredContent" in lst:
            lst = lst.get("structuredContent", {})
        sessions = lst.get("sessions", [])
        log("[OK] Sessions: {}".format(len(sessions)))
        for s in sessions:
            log("  - {}: {} analyzing={} active={}".format(
                s.get("session_id"), s.get("filename"),
                s.get("is_analyzing"), s.get("is_active")))
    except Exception as e:
        log("[ERROR] List failed: {}".format(e))

    # Close
    log("[INFO] Calling idalib_close...")
    try:
        r = rpc({"jsonrpc": "2.0", "id": 400, "method": "tools/call",
                 "params": {"name": "idalib_close", "arguments": {"session_id": "libp"}}})
        result = r.get("result", {})
        content = result.get("content", [{}])[0].get("text", "{}")
        close_res = json.loads(content)
        if "structuredContent" in close_res:
            close_res = close_res.get("structuredContent", {})
        log("[OK] Close: {}".format(json.dumps(close_res, indent=2)[:200]))
    except Exception as e:
        log("[ERROR] Close failed: {}".format(e))

    # Verify cleanup
    time.sleep(2)
    tmp_dir = Path(os.environ.get("TEMP", "/tmp"))
    temp_files = list(tmp_dir.glob("idalib_*libpersona*"))
    if temp_files:
        log("[WARN] Temp files still present: {}".format([str(f) for f in temp_files]))
    else:
        log("[OK] No temp files leaked")

    total = int(time.monotonic() - start_time)
    log("[SUCCESS] Full test completed in {}s".format(total))

    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    sup_stdout.close()
    sup_stderr.close()
    log_file.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
