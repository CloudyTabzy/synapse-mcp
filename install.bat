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

for /f "tokens=2 delims=. " %%a in ('python -c "import sys; print(sys.version_info.major)"') do set PY_MAJOR=%%a
for /f "tokens=2 delims=. " %%a in ('python -c "import sys; print(sys.version_info.minor)"') do set PY_MINOR=%%a

if %PY_MAJOR% LSS 3 (
    echo [ERROR] Python %PY_MAJOR%.%PY_MINOR% found, but 3.11+ is required.
    pause
    exit /b 1
)
if %PY_MAJOR%==3 if %PY_MINOR% LSS 11 (
    echo [ERROR] Python %PY_MAJOR%.%PY_MINOR% found, but 3.11+ is required.
    pause
    exit /b 1
)

echo [OK] Python %PY_MAJOR%.%PY_MINOR% detected.
echo.

:: --- Uninstall conflicting upstream packages --------------------------------
echo [1/5] Removing conflicting upstream packages...
pip uninstall -y ida-pro-mcp ida-pro-mcp-xjoker >nul 2>&1
echo [OK] Conflicting packages removed (if any).
echo.

:: --- Install this fork in editable mode -------------------------------------
echo [2/5] Installing ida-pro-triton-miasm-mcp from source...
cd /d "%~dp0"
pip install -e .
if errorlevel 1 (
    echo [ERROR] Installation failed. See error above.
    pause
    exit /b 1
)
echo [OK] Fork installed successfully.
echo.

:: --- Install the IDA plugin -------------------------------------------------
echo [3/5] Installing IDA Pro plugin...
ida-pro-mcp --install
if errorlevel 1 (
    echo [WARNING] IDA plugin installation reported an error.
    echo This is normal if IDA Pro is not currently running.
    echo The plugin will be available the next time you start IDA.
) else (
    echo [OK] IDA plugin installed.
)
echo.

:: --- Offer to install optional engines --------------------------------------
echo [4/5] Optional analysis engines:
echo.
echo   Triton  - Symbolic execution and SMT constraint solving
echo   Miasm   - IR lifting, SSA, deobfuscation, cross-arch assembly
echo.
choice /C TMB /N /M "Install optional engines? [T]riton only / [M]iasm only / [B]oth / [S]kip: "
if errorlevel 4 goto :skip_deps
if errorlevel 3 goto :install_both
if errorlevel 2 goto :install_miasm
if errorlevel 1 goto :install_triton

:install_triton
echo.
echo Installing Triton...
ida-pro-mcp --install-deps triton
goto :deps_done

:install_miasm
echo.
echo Installing Miasm...
ida-pro-mcp --install-deps miasm
goto :deps_done

:install_both
echo.
echo Installing both Triton and Miasm...
ida-pro-mcp --install-deps all
goto :deps_done

:skip_deps
echo Skipping optional engines.
goto :deps_done

:deps_done
echo.

:: --- Verification -----------------------------------------------------------
echo [5/5] Verifying installation...
echo.
echo Available CLI commands:
echo   ida-pro-mcp           (same as upstream, but enhanced)
echo   ida-triton-miasm-mcp  (fork-specific alias)
echo   ida-pro-mcp-enhanced  (fork-specific alias)
echo   idalib-mcp            (headless mode)
echo   ida-mcp-trace-dump    (trace export utility)
echo.

echo Checking tool registration...
python -c "from ida_pro_mcp.ida_mcp.api_tasks import task_submit; print('  task_submit    : OK')" 2>nul || echo   task_submit    : NOT LOADED (needs IDA context)
python -c "from ida_pro_mcp.ida_mcp.task_backend import InMemoryTaskBackend; print('  task_backend   : OK')" 2>nul || echo   task_backend   : FAILED

echo.
echo ============================================================
echo  Installation complete!
echo ============================================================
echo.
echo Next steps:
echo   1. Restart IDA Pro completely
echo   2. The MCP server will auto-start on http://127.0.0.1:13337
echo   3. Configure your MCP client to connect
echo.
echo To install optional engines later, run:
echo   ida-pro-mcp --install-deps triton
echo   ida-pro-mcp --install-deps miasm
echo   ida-pro-mcp --install-deps all
echo.
pause
