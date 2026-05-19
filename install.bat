@echo off
setlocal EnableDelayedExpansion

echo ============================================================
echo  IDA Pro Triton ^& Miasm MCP - Enhanced Fork Installer
echo  https://github.com/CloudyTabzy/ida-pro-triton-miasm-mcp
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
echo [1/4] Removing conflicting upstream packages...
pip uninstall -y ida-pro-mcp ida-pro-mcp-xjoker >nul 2>&1
echo [OK] Done.
echo.

:: --- Install this fork in editable mode -------------------------------------
echo [2/4] Installing ida-pro-triton-miasm-mcp from source...
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

:: --- Install the IDA plugin (with interactive TUI) --------------------------
echo [3/4] Installing IDA Pro plugin...
echo.
echo The installer will now launch the IDA plugin installer.
echo If prompted, use arrow keys + space to select optional engines
echo (Triton / Miasm), then press Enter to confirm.
echo.
pause

call ida-pro-mcp --install
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
echo [4/4] Optional analysis engines and binary tools
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
echo.

set INSTALL_TRITON=N
set INSTALL_MIASM=N
set INSTALL_CONSTRUCT=N
set INSTALL_CSTRUCT=N
set INSTALL_FILETYPE=N
set INSTALL_LIEF=N
set INSTALL_YARA=N

set /p CHOICE="Install ALL seven libraries? [Y/N] (default N): "
if /i "!CHOICE!"=="Y" (
    set INSTALL_TRITON=Y
    set INSTALL_MIASM=Y
    set INSTALL_CONSTRUCT=Y
    set INSTALL_CSTRUCT=Y
    set INSTALL_FILETYPE=Y
    set INSTALL_LIEF=Y
    set INSTALL_YARA=Y
) else (
    echo.
    set /p TRITON_CHOICE="  Install triton           (triton_*    tools)?  [Y/N]: "
    if /i "!TRITON_CHOICE!"=="Y" set INSTALL_TRITON=Y

    set /p MIASM_CHOICE="  Install miasm            (miasm_*     tools)?  [Y/N]: "
    if /i "!MIASM_CHOICE!"=="Y" set INSTALL_MIASM=Y

    set /p CONSTRUCT_CHOICE="  Install construct       (construct_*  tools)?  [Y/N]: "
    if /i "!CONSTRUCT_CHOICE!"=="Y" set INSTALL_CONSTRUCT=Y

    set /p CSTRUCT_CHOICE="  Install dissect.cstruct (cstruct_*  tools)?   [Y/N]: "
    if /i "!CSTRUCT_CHOICE!"=="Y" set INSTALL_CSTRUCT=Y

    set /p FILETYPE_CHOICE="  Install filetype        (filetype_*  tools)?  [Y/N]: "
    if /i "!FILETYPE_CHOICE!"=="Y" set INSTALL_FILETYPE=Y

    set /p LIEF_CHOICE="  Install lief            (lief_*      tools)?     [Y/N]: "
    if /i "!LIEF_CHOICE!"=="Y" set INSTALL_LIEF=Y

    set /p YARA_CHOICE="  Install yara-python    (yara_*      tools)?     [Y/N]: "
    if /i "!YARA_CHOICE!"=="Y" set INSTALL_YARA=Y
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

if "!ANY_INSTALLED!"=="N" (
    if "!INSTALL_TRITON!!INSTALL_MIASM!!INSTALL_CONSTRUCT!!INSTALL_CSTRUCT!!INSTALL_FILETYPE!!INSTALL_LIEF!!INSTALL_YARA!"=="NNNNNNN" (
        echo   [SKIP] No optional libraries selected.
    )
)

echo.
echo ============================================================
echo  Installation complete!
echo ============================================================
echo.
echo Available commands:
echo   ida-pro-mcp           (drop-in replacement for upstream)
echo   ida-triton-miasm-mcp  (fork alias)
echo   ida-pro-mcp-enhanced  (fork alias)
echo   idalib-mcp            (headless mode)
echo   ida-mcp-trace-dump    (trace export utility)
echo.
echo Next steps:
echo   1. Restart IDA Pro completely
echo   2. The MCP server auto-starts on http://127.0.0.1:13337
echo   3. Configure your MCP client to connect
echo.
echo Tip: To install analysis engines later, run:
echo   ida-pro-mcp --install-deps triton
echo   ida-pro-mcp --install-deps miasm
echo   ida-pro-mcp --install-deps yara
echo   pip install construct dissect.cstruct filetype lief yara-python
pause
