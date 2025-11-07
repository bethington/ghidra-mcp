#!/usr/bin/env python3
"""
Version Verification Script for GhidraMCP

This script ensures version consistency across all project files.
Run this before building to catch version mismatches.
"""

import re
import sys
from pathlib import Path

def extract_pom_version(pom_path):
    """Extract version from pom.xml"""
    with open(pom_path, 'r', encoding='utf-8') as f:
        content = f.read()
        match = re.search(r'<version>(\d+\.\d+\.\d+)</version>', content)
        if match:
            return match.group(1)
    return None

def extract_extension_version(ext_path):
    """Extract version from extension.properties"""
    with open(ext_path, 'r', encoding='utf-8') as f:
        content = f.read()
        match = re.search(r'version=\$\{project\.version\}', content)
        if match:
            return "Uses ${project.version} (dynamic)"
    return None

def check_hardcoded_versions(base_path):
    """Find hardcoded version references in scripts"""
    issues = []
    
    # Check deployment verifier
    verifier_path = base_path / 'scripts' / 'ghidra_plugin_deployment_verifier.py'
    if verifier_path.exists():
        with open(verifier_path, 'r', encoding='utf-8') as f:
            content = f.read()
            matches = re.findall(r'GhidraMCP-(\d+\.\d+\.\d+)\.zip', content)
            if matches:
                for version in set(matches):
                    issues.append(f"deployment_verifier.py references version {version}")
    
    return issues

def main():
    base_path = Path(__file__).parent.parent
    
    print("=" * 60)
    print("GhidraMCP Version Verification")
    print("=" * 60)
    print()
    
    # Check pom.xml version
    pom_path = base_path / 'pom.xml'
    pom_version = extract_pom_version(pom_path)
    
    if not pom_version:
        print("❌ ERROR: Could not extract version from pom.xml")
        sys.exit(1)
    
    print(f"✅ pom.xml version: {pom_version}")
    
    # Check extension.properties
    ext_path = base_path / 'src' / 'main' / 'resources' / 'extension.properties'
    ext_version = extract_extension_version(ext_path)
    
    if ext_version:
        print(f"✅ extension.properties: {ext_version}")
    else:
        print("❌ ERROR: extension.properties does not use dynamic versioning")
        sys.exit(1)
    
    # Check for hardcoded versions in scripts
    print()
    print("Checking for hardcoded version references...")
    issues = check_hardcoded_versions(base_path)
    
    if issues:
        print("⚠️  WARNING: Found hardcoded version references:")
        for issue in issues:
            print(f"   - {issue}")
        print()
        print("These should reference pom.xml version:", pom_version)
        
        # Check if they match current version
        all_match = all(pom_version in issue for issue in issues)
        if all_match:
            print("✅ All hardcoded versions match pom.xml")
        else:
            print("❌ ERROR: Hardcoded versions do not match pom.xml!")
            sys.exit(1)
    else:
        print("✅ No hardcoded version references found")
    
    print()
    print("=" * 60)
    print(f"✅ Version Verification Complete - Version: {pom_version}")
    print("=" * 60)
    print()
    print("Build will create:")
    print(f"   - target/GhidraMCP-{pom_version}.zip")
    print(f"   - target/GhidraMCP.jar")
    print()

if __name__ == "__main__":
    main()
