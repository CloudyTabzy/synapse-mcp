#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "  IDA Pro Triton & Miasm MCP - Enhanced Fork Installer"
echo "  https://github.com/CloudyTabzy/ida-pro-triton-miasm-mcp"
echo "============================================================"
echo

# --- Check Python version -----------------------------------------------------
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo 0)
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo 0)

if [ "$PY_MAJOR" -lt 3 ] || [ "$PY_MINOR" -lt 11 ]; then
    echo "[ERROR] Python ${PY_MAJOR}.${PY_MINOR} found, but 3.11+ is required."
    exit 1
fi

echo "[OK] Python ${PY_MAJOR}.${PY_MINOR} detected."
echo

# --- Uninstall conflicting upstream packages ----------------------------------
echo "[1/5] Removing conflicting upstream packages..."
pip3 uninstall -y ida-pro-mcp ida-pro-mcp-xjoker 2>/dev/null || true
echo "[OK] Conflicting packages removed (if any)."
echo

# --- Install this fork in editable mode ---------------------------------------
echo "[2/5] Installing ida-pro-triton-miasm-mcp from source..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
pip3 install -e .
echo "[OK] Fork installed successfully."
echo

# --- Install the IDA plugin ---------------------------------------------------
echo "[3/5] Installing IDA Pro plugin..."
ida-pro-mcp --install || {
    echo "[WARNING] IDA plugin installation reported an error."
    echo "This is normal if IDA Pro is not currently running."
    echo "The plugin will be available the next time you start IDA."
}
echo

# --- Offer to install optional engines ----------------------------------------
echo "[4/5] Optional analysis engines:"
echo
printf "  Triton  - Symbolic execution and SMT constraint solving\n"
printf "  Miasm   - IR lifting, SSA, deobfuscation, cross-arch assembly\n"
echo
read -rp "Install optional engines? [t]riton / [m]iasm / [b]oth / [s]kip: " choice
case "$choice" in
    [tT])
        echo "Installing Triton..."
        ida-pro-mcp --install-deps triton
        ;;
    [mM])
        echo "Installing Miasm..."
        ida-pro-mcp --install-deps miasm
        ;;
    [bB])
        echo "Installing both Triton and Miasm..."
        ida-pro-mcp --install-deps all
        ;;
    *)
        echo "Skipping optional engines."
        ;;
esac
echo

# --- Verification -------------------------------------------------------------
echo "[5/5] Verifying installation..."
echo
echo "Available CLI commands:"
echo "  ida-pro-mcp           (same as upstream, but enhanced)"
echo "  ida-triton-miasm-mcp  (fork-specific alias)"
echo "  ida-pro-mcp-enhanced  (fork-specific alias)"
echo "  idalib-mcp            (headless mode)"
echo "  ida-mcp-trace-dump    (trace export utility)"
echo

python3 -c "from ida_pro_mcp.ida_mcp.task_backend import InMemoryTaskBackend; print('  task_backend   : OK')" 2>/dev/null || echo "  task_backend   : FAILED"

echo
echo "============================================================"
echo "  Installation complete!"
echo "============================================================"
echo
echo "Next steps:"
echo "  1. Restart IDA Pro completely"
echo "  2. The MCP server will auto-start on http://127.0.0.1:13337"
echo "  3. Configure your MCP client to connect"
echo
echo "To install optional engines later, run:"
echo "  ida-pro-mcp --install-deps triton"
echo "  ida-pro-mcp --install-deps miasm"
echo "  ida-pro-mcp --install-deps all"
echo
