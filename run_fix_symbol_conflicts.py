#!/usr/bin/env python3
"""
Run FixSymbolConflicts_ProjectFolder.java script in Ghidra headless mode
"""

import subprocess
import sys
import os
from pathlib import Path

# Ghidra installation path - adjust if needed
GHIDRA_PATH = os.environ.get('GHIDRA_PATH', 'C:\\Program Files\\Ghidra')

# Project path
PROJECT_PATH = 'F:/D2VersionChanger/VersionChanger'

# Script path
SCRIPT_PATH = str(Path.home() / 'ghidra_scripts' / 'FixSymbolConflicts_ProjectFolder.java')

# Binary to analyze
BINARY_PATH = '/LoD/1.08/Storm.dll'

def run_script():
    """Run the FixSymbolConflicts script in headless mode"""
    
    print("=" * 70)
    print("RUNNING FIX SYMBOL CONFLICTS SCRIPT")
    print("=" * 70)
    print(f"Project: {PROJECT_PATH}")
    print(f"Binary:  {BINARY_PATH}")
    print(f"Script:  {SCRIPT_PATH}")
    print("")
    
    # Build the headless command
    cmd = [
        'analyzeHeadless',
        PROJECT_PATH,
        'temp_project',
        '-process',
        BINARY_PATH,
        '-scriptPath',
        str(Path.home() / 'ghidra_scripts'),
        '-preScript',
        'FixSymbolConflicts_ProjectFolder.java',
        '-deleteProject'
    ]
    
    print(f"Command: {' '.join(cmd)}")
    print("")
    
    try:
        # Change to Ghidra bin directory
        ghidra_bin = os.path.join(GHIDRA_PATH, 'bin')
        
        # Run the command
        result = subprocess.run(
            cmd,
            cwd=ghidra_bin,
            capture_output=False,
            text=True
        )
        
        if result.returncode == 0:
            print("\n" + "=" * 70)
            print("SUCCESS: Script completed")
            print("=" * 70)
        else:
            print("\n" + "=" * 70)
            print("ERROR: Script failed")
            print("=" * 70)
            sys.exit(1)
            
    except Exception as e:
        print(f"ERROR: Failed to run script: {e}")
        sys.exit(1)

if __name__ == '__main__':
    run_script()
