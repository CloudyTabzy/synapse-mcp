import sys

with open('install.bat', 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Find the angr block
start_marker = 'if "!INSTALL_ANGR!"=="Y" ('
end_marker = 'if "!ANY_INSTALLED!"=="N" ('

start_idx = content.find(start_marker)
end_idx = content.find(end_marker, start_idx)

if start_idx == -1 or end_idx == -1:
    print(f'Start: {start_idx}, End: {end_idx}')
    sys.exit(1)

print(f'Found block from {start_idx} to {end_idx}')

new_block = (
    'if "!INSTALL_ANGR!"=="Y" (\n'
    '    echo Installing angr - ~200 MB, this may take a while...\n'
    '    \n'
    '    :: Try to activate Visual Studio build environment so pip can compile native extensions\n'
    '    set VCVARS_FOUND=\n'
    '    \n'
    '    :: Try vswhere.exe first (most robust)\n'
    '    if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe" (\n'
    '        for /f "usebackq tokens=*" %%i in (`"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (\n'
    '            if exist "%%i\\VC\\Auxiliary\\Build\\vcvarsall.bat" (\n'
    '                echo   [INFO] Activating VS build environment from %%i\n'
    '                call "%%i\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 >/dev/null 2>&1\n'
    '                set VCVARS_FOUND=1\n'
    '            )\n'
    '        )\n'
    '    )\n'
    '    \n'
    '    :: Fallback: try common vcvarsall.bat paths\n'
    '    if not defined VCVARS_FOUND (\n'
    '        if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" (\n'
    '            echo   [INFO] Activating VS BuildTools 2022 x64 environment\n'
    '            call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 >/dev/null 2>&1\n'
    '        ) else if exist "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" (\n'
    '            echo   [INFO] Activating VS BuildTools 2022 x64 environment\n'
    '            call "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 >/dev/null 2>&1\n'
    '        ) else if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" (\n'
    '            echo   [INFO] Activating VS Community 2022 x64 environment\n'
    '            call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 >/dev/null 2>&1\n'
    '        ) else if exist "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" (\n'
    '            echo   [INFO] Activating VS Community 2022 x64 environment\n'
    '            call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 >/dev/null 2>&1\n'
    '        ) else if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" (\n'
    '            echo   [INFO] Activating VS BuildTools x64 environment\n'
    '            call "C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 >/dev/null 2>&1\n'
    '        ) else if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" (\n'
    '            echo   [INFO] Activating VS BuildTools 2019 x64 environment\n'
    '            call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 >/dev/null 2>&1\n'
    '        ) else (\n'
    '            echo   [WARNING] Could not find vcvarsall.bat - pip may fail on native extensions\n'
    '        )\n'
    '    )\n'
    '    \n'
    '    call pip install "angr>=9.2"\n'
    '    if errorlevel 1 (\n'
    '        echo   [WARNING] angr install failed.\n'
    '        echo   Common cause on Windows: Microsoft Visual C++ 14.0+ Build Tools required.\n'
    '        echo   Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/\n'
    '        echo   After installing Build Tools, run: pip install angr\n'
    '    ) else (\n'
    '        echo   [OK] angr installed.\n'
    '        set ANY_INSTALLED=Y\n'
    '    )\n'
    ')\n'
    '\n'
)

new_content = content[:start_idx] + new_block + content[end_idx:]

with open('install.bat', 'w', encoding='utf-8') as f:
    f.write(new_content)

print('install.bat fixed successfully')
