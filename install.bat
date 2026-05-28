@echo off
setlocal EnableDelayedExpansion

echo ============================================================
echo  Synapse MCP Installer
echo  https://github.com/CloudyTabzy/synapse-mcp
echo ============================================================
echo.

:: --- Check Python version ---------------------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "usebackq tokens=*" %%a in (`python -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}')"`) do set PY_VER=%%a

echo [OK] Python %PY_VER% detected.
echo.

:: --- Uninstall conflicting upstream packages --------------------------------
echo [1/5] Removing conflicting upstream packages...
pip uninstall -y ida-pro-mcp ida-pro-mcp >nul 2>&1
echo [OK] Done.
echo.

:: --- Install this fork in editable mode -------------------------------------
echo [2/5] Installing synapse-mcp from source...
cd /d "%~dp0"
pip install -e . >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip install failed. Trying with output...
    pip install -e .
    pause
    exit /b 1
)
echo [OK] Fork installed successfully.
echo.

:: --- Context mode selection --------------------------------------------------
echo [3a/5] Context Window Mode
echo -------------------------------------------------------
echo synapse-mcp exposes 160+ tools. Without lazy mode, ALL schemas are sent
echo to the agent on every session start, consuming ~40K tokens before any
echo real work begins. Lazy mode cuts that to ~800 tokens.
echo.
echo  LAZY MODE  (recommended)
echo    The agent sees 4 meta-tools at startup:
echo      list_modules   - discover groups: core / symbolic / graph / formats
echo      list_tools     - list tools in a group with one-line descriptions
echo      describe_tool  - get full schema for any single tool
echo      invoke_tool    - call any tool by name
echo    Context usage: ~800 tokens at startup, schemas fetched on demand.
echo    Works with all MCP clients. No extra dependencies.
echo.
echo  NORMAL MODE
echo    All 160+ tools exposed upfront.
echo    Use only if your AI client has a very large context window
echo    or you need direct tool access without the invoke_tool wrapper.
echo.

set LAZY_MODE=N
set /p LAZY_CHOICE="Enable lazy mode? [Y/N] (default Y): "
if /i "!LAZY_CHOICE!"=="" set LAZY_CHOICE=Y
if /i "!LAZY_CHOICE!"=="Y" (
    set LAZY_MODE=Y
    echo [OK] Lazy mode selected.
) else (
    echo [OK] Normal mode selected.
)
echo.

:: --- Install the IDA plugin (with interactive TUI) --------------------------
echo [3b/5] Installing IDA Pro plugin...
echo.
echo The installer will now launch the IDA plugin installer.
echo If prompted, use arrow keys + space to select optional engines
echo (Triton / Miasm / Angr), then press Enter to confirm.
echo.
pause

if "!LAZY_MODE!"=="Y" (
    call ida-pro-mcp --install --lazy
) else (
    call ida-pro-mcp --install
)
if errorlevel 1 (
    echo.
    echo [WARNING] IDA plugin installation may have encountered an issue.
    echo This is normal if IDA Pro is not currently running.
    echo The plugin will be available the next time you start IDA.
    echo.
    pause
)

:: --- Optional analysis engine libraries --------------------------------
echo.
echo [4/5] Optional analysis engines and binary tools
echo ----------------------------------------------------
echo These libraries add advanced binary analysis capabilities to the plugin.
echo Each is independently optional.
echo.
echo   triton         - triton_*    tools  (symbolic execution, SMT solving, taint)
echo   miasm          - miasm_*     tools  (IR lifting, SSA, deobfuscation)
echo   construct      - construct_*  tools  (declarative binary format grammar)
echo   dissect.cstruct - cstruct_*  tools  (C-syntax struct/enum/typedef parsing)
echo   filetype       - filetype_*  tools  (magic-byte file type identification)
echo   lief           - lief_*      tools  (PE/ELF/Mach-O analysis, Authenticode,
echo                                          Rich Header, CFG guard table, IDB diff)
echo   yara           - yara_*      tools  (signature-based scanning, crypto detection,
echo                                          threat profiling, function annotation)
echo   angr           - angr_*      tools  (symbolic execution, path exploration,
echo                                          crackme solving, CFG recovery)
echo                    NOTE: angr is ~200 MB - the install will show live progress.
echo   networkx       - nx_*        tools  (call-graph centrality, community detection,
echo                                          SCCs, paths, dominators, graph diff)
echo.

set INSTALL_TRITON=N
set INSTALL_MIASM=N
set INSTALL_CONSTRUCT=N
set INSTALL_CSTRUCT=N
set INSTALL_FILETYPE=N
set INSTALL_LIEF=N
set INSTALL_YARA=N
set INSTALL_ANGR=N
set INSTALL_NETWORKX=N

set /p CHOICE="Install ALL nine libraries? [Y/N] (default N): "
if /i "!CHOICE!"=="Y" (
    set INSTALL_TRITON=Y
    set INSTALL_MIASM=Y
    set INSTALL_CONSTRUCT=Y
    set INSTALL_CSTRUCT=Y
    set INSTALL_FILETYPE=Y
    set INSTALL_LIEF=Y
    set INSTALL_YARA=Y
    set INSTALL_ANGR=Y
    set INSTALL_NETWORKX=Y
) else (
    echo.
    set /p TRITON_CHOICE="  Install triton           (triton_*    tools)?  [Y/N]: "
    if /i "!TRITON_CHOICE!"=="Y" set INSTALL_TRITON=Y

    set /p MIASM_CHOICE="  Install miasm            (miasm_*     tools)?  [Y/N]: "
    if /i "!MIASM_CHOICE!"=="Y" set INSTALL_MIASM=Y

    set /p ANGR_CHOICE="  Install angr             (angr_*      tools)?  [Y/N]: "
    if /i "!ANGR_CHOICE!"=="Y" set INSTALL_ANGR=Y

    set /p CONSTRUCT_CHOICE="  Install construct        (construct_* tools)?  [Y/N]: "
    if /i "!CONSTRUCT_CHOICE!"=="Y" set INSTALL_CONSTRUCT=Y

    set /p CSTRUCT_CHOICE="  Install dissect.cstruct  (cstruct_*   tools)?  [Y/N]: "
    if /i "!CSTRUCT_CHOICE!"=="Y" set INSTALL_CSTRUCT=Y

    set /p FILETYPE_CHOICE="  Install filetype         (filetype_*  tools)?  [Y/N]: "
    if /i "!FILETYPE_CHOICE!"=="Y" set INSTALL_FILETYPE=Y

    set /p LIEF_CHOICE="  Install lief             (lief_*      tools)?  [Y/N]: "
    if /i "!LIEF_CHOICE!"=="Y" set INSTALL_LIEF=Y

    set /p YARA_CHOICE="  Install yara-python      (yara_*      tools)?  [Y/N]: "
    if /i "!YARA_CHOICE!"=="Y" set INSTALL_YARA=Y

    set /p NETWORKX_CHOICE="  Install networkx         (nx_*        tools)?  [Y/N]: "
    if /i "!NETWORKX_CHOICE!"=="Y" set INSTALL_NETWORKX=Y
)

echo.
set ANY_INSTALLED=N

if "!INSTALL_TRITON!"=="Y" (
    echo Installing triton-library...
    pip install triton-library >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] triton install failed. Run manually: pip install triton-library
    ) else (
        echo   [OK] triton installed.
        set ANY_INSTALLED=Y
    )
)

if "!INSTALL_MIASM!"=="Y" (
    echo Installing miasm...
    pip install "miasm>=0.1.5" "future>=0.18.0" >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] miasm install failed. Run manually: pip install miasm future
    ) else (
        echo   [OK] miasm installed.
        set ANY_INSTALLED=Y
    )
)

if "!INSTALL_CONSTRUCT!"=="Y" (
    echo Installing construct...
    pip install construct >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] construct install failed. Run manually: pip install construct
    ) else (
        echo   [OK] construct installed.
        set ANY_INSTALLED=Y
    )
)

if "!INSTALL_CSTRUCT!"=="Y" (
    echo Installing dissect.cstruct...
    pip install "dissect.cstruct" >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] dissect.cstruct install failed. Run manually: pip install dissect.cstruct
    ) else (
        echo   [OK] dissect.cstruct installed.
        set ANY_INSTALLED=Y
    )
)

if "!INSTALL_FILETYPE!"=="Y" (
    echo Installing filetype...
    pip install filetype >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] filetype install failed. Run manually: pip install filetype
    ) else (
        echo   [OK] filetype installed.
        set ANY_INSTALLED=Y
    )
)

if "!INSTALL_LIEF!"=="Y" (
    echo Installing lief...
    pip install "lief>=0.15.0" >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] lief install failed. Run manually: pip install lief
    ) else (
        echo   [OK] lief installed.
        set ANY_INSTALLED=Y
    )
)

if "!INSTALL_YARA!"=="Y" (
    echo Installing yara-python...
    pip install "yara-python>=4.3.0" >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] yara-python install failed. Run manually: pip install yara-python
    ) else (
        echo   [OK] yara-python installed.
        set ANY_INSTALLED=Y
    )
)

if "!INSTALL_ANGR!"=="Y" (
    echo/
    echo ----------------------------------------------------------------
    echo  angr requires Visual Studio Build Tools to compile on Windows
    echo  and is therefore deferred. Install it manually after VS is set up:
    echo    pip install angr
    echo ----------------------------------------------------------------
    echo   [SKIP] angr deferred.
)

if "!INSTALL_NETWORKX!"=="Y" (
    echo Installing networkx...
    pip install "networkx>=3.0" >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] networkx install failed. Run manually: pip install networkx
    ) else (
        echo   [OK] networkx installed.
        set ANY_INSTALLED=Y
    )
)

if "!ANY_INSTALLED!"=="N" (
    if "!INSTALL_TRITON!!INSTALL_MIASM!!INSTALL_CONSTRUCT!!INSTALL_CSTRUCT!!INSTALL_FILETYPE!!INSTALL_LIEF!!INSTALL_YARA!!INSTALL_ANGR!!INSTALL_NETWORKX!"=="NNNNNNNNN" (
        echo   [SKIP] No optional libraries selected.
    )
)

:: --- TOON server-side encoding (separate from IDA-side engines) ---------------
echo.
echo [4b/5] Server-side token compression
echo -------------------------------------------------------
echo toon_format auto-compresses large list responses from tools like
echo lief_exports, list_functions_enhanced, find_function_prologues, and
echo get_bulk_function_hashes — ~40%% fewer tokens on qualifying calls.
echo This installs into the MCP server's Python (NOT IDA's Python).
echo.
set /p TOON_CHOICE="Install toon_format (TOON response compression)?  [Y/N] (default N): "
if /i "!TOON_CHOICE!"=="" set TOON_CHOICE=N
if /i "!TOON_CHOICE!"=="Y" (
    echo Installing toon_format...
    pip install toon_format >nul 2>&1
    if errorlevel 1 (
        echo   [WARNING] toon_format install failed. Run manually: pip install toon_format
    ) else (
        echo   [OK] toon_format installed — large list responses will be auto-compressed.
    )
) else (
    echo   [SKIP] toon_format skipped. Run later: pip install toon_format
)

:: --- Show MCP config to paste ------------------------------------------------
echo.
echo [5/5] MCP Client Configuration
echo -------------------------------------------------------
echo Copy the JSON below into your MCP client's config file.
echo (Claude Desktop: claude_desktop_config.json -- Claude Code: .claude/settings.json)
echo.

if "!LAZY_MODE!"=="Y" (
    ida-pro-mcp --config --lazy
) else (
    ida-pro-mcp --config
)

echo.
echo ============================================================
echo  Installation complete!
echo ============================================================
echo.
echo Available commands:
echo   ida-pro-mcp           (drop-in replacement for upstream)
echo   synapse-mcp           (primary command)
echo   idalib-mcp            (headless mode)
echo   ida-mcp-trace-dump    (trace export utility)
echo.
if "!LAZY_MODE!"=="Y" (
    echo Mode: LAZY   -- 4 meta-tools at startup. Agents call invoke_tool^("name", args^) to use any tool.
    echo Switch off:     add --no-lazy to the MCP config args for a session, or reinstall without lazy.
    echo Regenerate:     ida-pro-mcp --config --lazy
) else (
    echo Mode: NORMAL -- 160+ tools exposed at startup.
    echo Switch on:      add --lazy to the MCP config args, or reinstall with lazy mode.
    echo Regenerate:     ida-pro-mcp --config
)
echo.
echo Next steps:
echo   1. Restart IDA Pro completely
echo   2. The MCP server auto-starts on http://127.0.0.1:13337
echo   3. Paste the config above into your MCP client
echo.
echo To install analysis engines later:
echo   ida-pro-mcp --install-deps triton
echo   ida-pro-mcp --install-deps miasm
echo   ida-pro-mcp --install-deps lief
echo   ida-pro-mcp --install-deps yara
echo   ida-pro-mcp --install-deps networkx
echo   pip install angr construct dissect.cstruct filetype
echo.
echo To enable server-side TOON response compression later:
echo   pip install toon_format
pause
