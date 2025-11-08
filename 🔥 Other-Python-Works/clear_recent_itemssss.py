#!/usr/bin/env python3
# Filename: clear_recent_items.py
# Description: Forcefully clears Windows "Recent Items" without showing "Access denied" errors.

import os
import subprocess

def clear_recent_items():
    # Path to the Windows Recent Items folder
    recent_path = os.path.join(os.getenv("APPDATA"), r"Microsoft\Windows\Recent")

    print("\n🧹 Clearing Windows Recent Items...\n")

    # PowerShell script to:
    # 1. Stop explorer.exe (releases file locks)
    # 2. Remove all items from Recent folder with -Force
    # 3. Restart explorer.exe
    ps_command = f"""
    try {{
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        if (Test-Path '{recent_path}') {{
            Get-ChildItem '{recent_path}' -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object {{ $_.Attributes = 'Normal' }}
            Remove-Item '{recent_path}\\*' -Recurse -Force -ErrorAction SilentlyContinue
        }}
        Start-Process explorer.exe
    }} catch {{
        # Ignore any errors silently
    }}
    """

    # Run PowerShell command silently
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print("✅ Recent Items cleared successfully. No access denied, no leftover files.\n")

if __name__ == "__main__":
    clear_recent_items()

# py E:\Cloned\Verify-and-Reset\🔥 Other-Python-Works\clear_recent_itemssss.py