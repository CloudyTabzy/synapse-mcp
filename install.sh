#!/usr/bin/env bash
set -e

echo "============================================================"
echo "  Synapse MCP Installer"
echo "  https://github.com/CloudyTabzy/synapse-mcp"
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
echo "[1/4] Removing conflicting upstream packages..."
pip3 uninstall -y ida-pro-mcp ida-pro-mcp-xjoker 2>/dev/null || true
echo "[OK] Done."
echo

# --- Install this fork in editable mode ---------------------------------------
echo "[2/4] Installing synapse-mcp from source..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
pip3 install -e . >/dev/null 2>&1 || pip3 install -e .
echo "[OK] Fork installed successfully."
echo

# --- Install the IDA plugin (with interactive TUI) ----------------------------
echo "[3/4] Installing IDA Pro plugin..."
echo
echo "The installer will now launch the IDA plugin installer."
echo "If prompted, use arrow keys + space to select optional engines"
echo "(Triton / Miasm), then press Enter to confirm."
echo
read -rp "Press Enter to continue..."

ida-pro-mcp --install || {
    echo
    echo "[WARNING] IDA plugin installation may have encountered an issue."
    echo "This is normal if IDA Pro is not currently running."
    echo "The plugin will be available the next time you start IDA."
}

# --- Optional analysis engine libraries --------------------------------
echo
echo "[4/4] Optional analysis engines and binary tools"
echo "----------------------------------------------------"
echo "These libraries add advanced binary analysis capabilities to the plugin."
echo "Each is independently optional."
echo
echo "  triton         - triton_*    tools  (symbolic execution, SMT solving, taint)"
echo "  miasm          - miasm_*     tools  (IR lifting, SSA, deobfuscation)"
echo "  construct      - construct_* tools  (declarative binary format grammar)"
echo "  dissect.cstruct - cstruct_*  tools  (C-syntax struct/enum/typedef parsing)"
echo "  filetype       - filetype_*  tools  (magic-byte file type identification)"
echo "  lief           - lief_*      tools  (PE/ELF/Mach-O analysis, Authenticode,"
echo "                                          Rich Header, CFG guard table, IDB diff)"
echo "  yara           - yara_*      tools  (signature-based scanning, crypto detection,"
echo "                                          threat profiling, function annotation)"
echo "  angr           - angr_*      tools  (symbolic execution, path exploration,"
echo "                                          crackme solving, CFG recovery)"
echo "                    NOTE: angr is ~200 MB - the install will show live progress."
echo

INSTALL_TRITON=n
INSTALL_MIASM=n
INSTALL_CONSTRUCT=n
INSTALL_CSTRUCT=n
INSTALL_FILETYPE=n
INSTALL_LIEF=n
INSTALL_YARA=n
INSTALL_ANGR=n

read -rp "Install ALL eight libraries? [y/N] (default N): " CHOICE
if [[ "${CHOICE,,}" == "y" ]]; then
    INSTALL_TRITON=y
    INSTALL_MIASM=y
    INSTALL_CONSTRUCT=y
    INSTALL_CSTRUCT=y
    INSTALL_FILETYPE=y
    INSTALL_LIEF=y
    INSTALL_YARA=y
    INSTALL_ANGR=y
else
    echo
    read -rp "  Install triton           (triton_*    tools)?  [y/N]: " TR
    [[ "${TR,,}" == "y" ]] && INSTALL_TRITON=y

    read -rp "  Install miasm            (miasm_*     tools)?  [y/N]: " MI
    [[ "${MI,,}" == "y" ]] && INSTALL_MIASM=y

    read -rp "  Install angr             (angr_*      tools)?  [y/N]: " AN
    [[ "${AN,,}" == "y" ]] && INSTALL_ANGR=y

    read -rp "  Install construct        (construct_* tools)?  [y/N]: " C
    [[ "${C,,}" == "y" ]] && INSTALL_CONSTRUCT=y

    read -rp "  Install dissect.cstruct  (cstruct_*   tools)?  [y/N]: " CS
    [[ "${CS,,}" == "y" ]] && INSTALL_CSTRUCT=y

    read -rp "  Install filetype         (filetype_*  tools)?  [y/N]: " FT
    [[ "${FT,,}" == "y" ]] && INSTALL_FILETYPE=y

    read -rp "  Install lief             (lief_*      tools)?  [y/N]: " LF
    [[ "${LF,,}" == "y" ]] && INSTALL_LIEF=y

    read -rp "  Install yara-python      (yara_*      tools)?  [y/N]: " YA
    [[ "${YA,,}" == "y" ]] && INSTALL_YARA=y
fi

echo
ANY_INSTALLED=n

if [[ "$INSTALL_TRITON" == "y" ]]; then
    echo "Installing triton-library..."
    if pip3 install triton-library >/dev/null 2>&1; then
        echo "  [OK] triton installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] triton install failed. Run manually: pip3 install triton-library"
    fi
fi

if [[ "$INSTALL_MIASM" == "y" ]]; then
    echo "Installing miasm..."
    if pip3 install "miasm>=0.1.5" "future>=0.18.0" >/dev/null 2>&1; then
        echo "  [OK] miasm installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] miasm install failed. Run manually: pip3 install miasm future"
    fi
fi

if [[ "$INSTALL_CONSTRUCT" == "y" ]]; then
    echo "Installing construct..."
    if pip3 install construct >/dev/null 2>&1; then
        echo "  [OK] construct installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] construct install failed. Run manually: pip3 install construct"
    fi
fi

if [[ "$INSTALL_CSTRUCT" == "y" ]]; then
    echo "Installing dissect.cstruct..."
    if pip3 install "dissect.cstruct" >/dev/null 2>&1; then
        echo "  [OK] dissect.cstruct installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] dissect.cstruct install failed. Run manually: pip3 install dissect.cstruct"
    fi
fi

if [[ "$INSTALL_FILETYPE" == "y" ]]; then
    echo "Installing filetype..."
    if pip3 install filetype >/dev/null 2>&1; then
        echo "  [OK] filetype installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] filetype install failed. Run manually: pip3 install filetype"
    fi
fi

if [[ "$INSTALL_LIEF" == "y" ]]; then
    echo "Installing lief..."
    if pip3 install "lief>=0.15.0" >/dev/null 2>&1; then
        echo "  [OK] lief installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] lief install failed. Run manually: pip3 install lief"
    fi
fi

if [[ "$INSTALL_YARA" == "y" ]]; then
    echo "Installing yara-python..."
    if pip3 install "yara-python>=4.3.0" >/dev/null 2>&1; then
        echo "  [OK] yara-python installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] yara-python install failed. Run manually: pip3 install yara-python"
    fi
fi

if [[ "$INSTALL_ANGR" == "y" ]]; then
    echo "Installing angr - ~200 MB, this may take a while..."
    if pip3 install "angr>=9.2"; then
        echo "  [OK] angr installed."
        ANY_INSTALLED=y
    else
        echo "  [WARNING] angr install failed."
        echo "  Common cause: missing system compiler for native extensions."
        echo "  On Windows: install Microsoft Visual C++ 14.0+ Build Tools"
        echo "    from https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        echo "  After installing, run: pip3 install angr"
    fi
fi

if [[ "$ANY_INSTALLED" == "n" ]]; then
    echo "  [SKIP] No optional libraries selected."
fi

echo
echo "============================================================"
echo "  Installation complete!"
echo "============================================================"
echo
echo "Available commands:"
echo "  ida-pro-mcp           (drop-in replacement for upstream)"
echo "  synapse-mcp           (primary command)"
echo "  idalib-mcp            (headless mode)"
echo "  ida-mcp-trace-dump    (trace export utility)"
echo
echo "Next steps:"
echo "  1. Restart IDA Pro completely"
echo "  2. The MCP server auto-starts on http://127.0.0.1:13337"
echo "  3. Configure your MCP client to connect"
echo
echo "Tip: To install analysis engines later, run:"
echo "  ida-pro-mcp --install-deps triton"
echo "  ida-pro-mcp --install-deps miasm"
echo "  ida-pro-mcp --install-deps yara"
echo "  pip3 install angr construct dissect.cstruct filetype lief yara-python"
echo
