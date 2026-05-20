#!/usr/bin/env python3
"""Install angr with the VS Build Tools x64 environment activated."""

import os
import subprocess
import sys


def main():
    vcvars_path = (
        r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"
        r"\VC\Auxiliary\Build\vcvarsall.bat"
    )

    print("============================================================")
    print(" angr Installer")
    print("============================================================")
    print()

    if not os.path.exists(vcvars_path):
        print("[WARNING] vcvarsall.bat not found.")
        print(f"  Expected: {vcvars_path}")
        print("  Angr may fail to build if VS Build Tools are not configured.")
    else:
        print("[INFO] Activating VS Build Tools x64 environment...")

        # Run vcvarsall + pip install in ONE shell=True call so the
        # environment from vcvarsall persists into the pip subprocess.
        shell_cmd = (
            f'"{vcvars_path}" x64 && '
            f'"{sys.executable}" -m pip install angr>=9.2 2>&1'
        )

        result = subprocess.run(
            shell_cmd,
            capture_output=True,
            text=True,
            shell=True,
        )
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        print(f"\n[returncode: {result.returncode}]")
        if result.returncode == 0:
            print()
            print("[OK] angr installed successfully.")
        else:
            print()
            print("[ERROR] angr install failed.")
            print(
                "\nEnsure 'Desktop development with C++' workload is installed:\n"
                "  https://visualstudio.microsoft.com/visual-cpp-build-tools/"
            )
            input("\nPress Enter to exit...")
            sys.exit(1)
            print()
            print("[OK] angr installed successfully.")
        else:
            print()
            print("[ERROR] angr install failed.")
            print(
                "\nEnsure 'Desktop development with C++' workload is installed:\n"
                "  https://visualstudio.microsoft.com/visual-cpp-build-tools/"
            )
            input("\nPress Enter to exit...")
            sys.exit(1)

    input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()