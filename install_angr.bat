@echo off
setlocal EnableDelayedExpansion

echo ============================================================
echo  angr Installer
echo ============================================================
echo.

:: --- Activate Visual Studio Build Tools for native extensions ---
echo [INFO] Activating VS Build Tools x64 environment...
python -c "import os, subprocess, sys; vcvars=r'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'; sys.exit(0 if os.path.exists(vcvars) else 1)" 2>nul
if errorlevel 1 (
    echo [WARNING] vcvarsall.bat not found.
    echo   Expected: C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat
    echo   Angr may fail to build if VS Build Tools are not properly configured.
) else (
    call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
    echo [OK] VS Build Tools x64 environment activated.
)

echo.
echo Installing angr (~200 MB, may take several minutes)...
pip install angr^>=9.2
if errorlevel 1 (
    echo.
    echo [ERROR] angr install failed.
    echo.
    echo Ensure Visual Studio Build Tools x64 native tools are installed:
    echo   https://visualstudio.microsoft.com/visual-cpp-build-tools/
    pause
    exit /b 1
)

echo.
echo [OK] angr installed successfully.
pause
    exit /b 1
)

echo.
echo [OK] angr installed successfully.
pause