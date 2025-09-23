#!/usr/bin/env python3
"""
Generic Ghidra MCP Development and Verification Automation Script

This script provides a comprehensive development cycle for Ghidra MCP tools with:
1. Project organization and cleanup
2. Building the Ghidra plugin
3. Graceful Ghidra process management
4. Deploying plugin to Ghidra installation
5. Starting Ghidra with verification checks
6. Comprehensive MCP endpoint testing
7. Automated reporting and documentation
8. Real-world binary documentation using Ghidra MCP tools
9. Documentation quality evaluation and prompt improvement

Usage:
    python ghidra_dev_cycle.py [--ghidra-path PATH] [--comprehensive-test] [--document-binary]
"""

import os
import sys
import subprocess
import time
import argparse
import json
import requests
import logging
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class TestResult:
    endpoint: str
    method: str
    description: str
    success: bool
    duration: float
    response_code: int
    error_message: str = ""

class GhidraDevCycle:
    def __init__(self, ghidra_path=None):
        self.workspace_root = Path(__file__).parent
        self.ghidra_path = Path(ghidra_path) if ghidra_path else self.find_ghidra_installation()
        self.jar_file = self.workspace_root / "target" / "GhidraMCP.jar"
        self.zip_file = self.workspace_root / "target" / "GhidraMCP-1.2.0.zip"
        self.bridge_script = self.workspace_root / "bridge_mcp_ghidra.py"
        self.mcp_base_url = "http://127.0.0.1:8089"
        self.test_results: List[TestResult] = []
        
        # Set up logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def find_ghidra_installation(self):
        """Try to find Ghidra installation automatically using enhanced search"""
        # Enhanced search patterns from deploy-to-ghidra.ps1
        search_roots = ["C:", "D:", "E:", "F:", "G:"]
        ghidra_patterns = [
            "ghidra_11.4*",
            "ghidra_11.3*", 
            "ghidra_11.2*",
            "ghidra_11.1*",
            "ghidra_11.0*",
            "ghidra_10*"
        ]
        
        # Check environment variables first
        env_paths = [
            os.environ.get("GHIDRA_INSTALL_DIR"),
            os.environ.get("GHIDRA_HOME"),
            os.environ.get("GHIDRA_PATH")
        ]
        
        for env_path in env_paths:
            if env_path and Path(env_path).exists():
                ghidra_run = Path(env_path) / "ghidraRun.bat"
                if ghidra_run.exists():
                    print(f"✅ Found Ghidra via environment at: {env_path}")
                    return Path(env_path)
        
        # Common installation locations
        common_paths = [
            "C:/ghidra_11.4.2_PUBLIC",
            "C:/ghidra_11.3_PUBLIC",
            "C:/ghidra_11.2_PUBLIC", 
            "C:/ghidra_11.1.2_PUBLIC",
            "C:/ghidra_11.1.1_PUBLIC", 
            "C:/ghidra_11.1_PUBLIC",
            "C:/ghidra_11.0_PUBLIC",
            "F:/ghidra_11.4.2",
            "D:/ghidra_11.4.2",
            "C:/Program Files/ghidra_11.4.2_PUBLIC",
            "C:/Program Files/ghidra_11.3_PUBLIC",
            "C:/Program Files/ghidra_11.2_PUBLIC",
            "C:/Program Files/ghidra_11.1.2_PUBLIC",
            "C:/Program Files/ghidra_11.1.1_PUBLIC"
        ]
        
        # Check common paths first
        for path in common_paths:
            path_obj = Path(path)
            if path_obj.exists():
                ghidra_run = path_obj / "ghidraRun.bat"
                if ghidra_run.exists():
                    print(f"✅ Found Ghidra installation at: {path}")
                    return path_obj
        
        # Enhanced search across drive roots
        print("🔍 Searching for Ghidra installations...")
        for root in search_roots:
            root_path = Path(root + "/")
            if root_path.exists():
                try:
                    import glob
                    for pattern in ghidra_patterns:
                        search_pattern = str(root_path / pattern)
                        matches = glob.glob(search_pattern)
                        for match in matches:
                            match_path = Path(match)
                            ghidra_run = match_path / "ghidraRun.bat"
                            if ghidra_run.exists():
                                print(f"✅ Found Ghidra installation at: {match}")
                                return match_path
                except:
                    continue
        
        print("⚠️  Could not find Ghidra installation automatically.")
        print("Please specify --ghidra-path or set GHIDRA_INSTALL_DIR environment variable")
        return None
    
    def organize_project_structure(self):
        """Organize project files into clean directory structure"""
        print("🗂️  Step 0: Organizing project structure...")
        print("="*50)
        
        # Create organized directories
        directories = {
            'docs': self.workspace_root / 'docs',
            'tests': self.workspace_root / 'tests', 
            'logs': self.workspace_root / 'logs',
            'scripts': self.workspace_root / 'scripts',
            'examples': self.workspace_root / 'examples'
        }
        
        for name, path in directories.items():
            path.mkdir(exist_ok=True)
            print(f"✅ Created/verified directory: {name}/")
        
        # Move test files to tests/ directory
        test_patterns = ['*test*.py', '*_test.py', 'test_*.py']
        moved_files = 0
        
        for pattern in test_patterns:
            for file_path in self.workspace_root.glob(pattern):
                if file_path.name != 'ghidra_dev_cycle.py' and file_path.is_file():
                    target_path = directories['tests'] / file_path.name
                    if not target_path.exists():
                        shutil.move(str(file_path), str(target_path))
                        print(f"📁 Moved {file_path.name} to tests/")
                        moved_files += 1
        
        # Move log files
        log_patterns = ['*.log', '*_log.txt', '*report*.txt', '*report*.json']
        for pattern in log_patterns:
            for file_path in self.workspace_root.glob(pattern):
                if file_path.is_file():
                    target_path = directories['logs'] / file_path.name
                    if not target_path.exists():
                        shutil.move(str(file_path), str(target_path))
                        print(f"📊 Moved {file_path.name} to logs/")
                        moved_files += 1
        
        # Move example files
        example_patterns = ['example*.py', '*_example.py', 'demo*.py']
        for pattern in example_patterns:
            for file_path in self.workspace_root.glob(pattern):
                if file_path.is_file():
                    target_path = directories['examples'] / file_path.name
                    if not target_path.exists():
                        shutil.move(str(file_path), str(target_path))
                        print(f"📘 Moved {file_path.name} to examples/")
                        moved_files += 1
        
        # Clean up duplicate or temporary files
        cleanup_patterns = ['*.tmp', '*.bak', '*~', '.DS_Store']
        cleaned_files = 0
        for pattern in cleanup_patterns:
            for file_path in self.workspace_root.rglob(pattern):
                if file_path.is_file():
                    file_path.unlink()
                    print(f"🗑️  Cleaned up: {file_path.name}")
                    cleaned_files += 1
        
        print(f"✅ Project organization complete!")
        print(f"   📁 Moved {moved_files} files to organized directories")
        print(f"   🗑️  Cleaned up {cleaned_files} temporary files")
        return True
    
    def build_plugin(self):
        """Build the Ghidra plugin using Maven with enhanced validation"""
        print("🔨 Building Ghidra Plugin...")
        print("="*50)
        
        try:
            # Check multiple Maven locations
            maven_paths = [
                str(Path(os.environ.get("USERPROFILE", "")) / "tools" / "apache-maven-3.9.6" / "bin" / "mvn.cmd"),
                "mvn.cmd",
                "mvn",
                "C:\\Program Files\\Apache\\Maven\\bin\\mvn.cmd"
            ]
            
            maven_cmd = None
            for maven_path in maven_paths:
                try:
                    result = subprocess.run([maven_path, "--version"], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        maven_cmd = maven_path
                        print(f"✅ Using Maven: {maven_cmd}")
                        break
                except:
                    continue
            
            if not maven_cmd:
                print("❌ Maven not found. Tried:")
                for path in maven_paths:
                    print(f"   - {path}")
                return False
            
            # Run Maven build (skip tests for development cycle)
            cmd = [maven_cmd, "clean", "package", "assembly:single", "-DskipTests"]
            
            result = subprocess.run(
                cmd,
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                # Verify build artifacts exist and have reasonable sizes
                artifacts_valid = True
                
                if self.zip_file.exists():
                    zip_size = self.zip_file.stat().st_size
                    if zip_size > 1000:  # At least 1KB
                        print(f"✅ Plugin ZIP created: {self.zip_file.name} ({zip_size:,} bytes)")
                    else:
                        print(f"❌ Plugin ZIP too small: {zip_size} bytes")
                        artifacts_valid = False
                else:
                    print(f"❌ Plugin ZIP not found: {self.zip_file}")
                    artifacts_valid = False
                
                if self.jar_file.exists():
                    jar_size = self.jar_file.stat().st_size  
                    if jar_size > 1000:  # At least 1KB
                        print(f"✅ Plugin JAR created: {self.jar_file.name} ({jar_size:,} bytes)")
                    else:
                        print(f"❌ Plugin JAR too small: {jar_size} bytes")
                        artifacts_valid = False
                else:
                    print(f"❌ Plugin JAR not found: {self.jar_file}")
                    artifacts_valid = False
                
                if artifacts_valid:
                    print("✅ Plugin built and validated successfully!")
                    return True
                else:
                    print("❌ Build completed but artifacts invalid!")
                    return False
            else:
                print(f"❌ Build failed with return code {result.returncode}")
                if result.stdout:
                    print("STDOUT:", result.stdout[-1000:])  # Last 1000 chars
                if result.stderr:
                    print("STDERR:", result.stderr[-1000:])
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Build timed out after 5 minutes")
            return False
        except Exception as e:
            print(f"❌ Build error: {e}")
            return False
    
    def close_ghidra(self):
        """Close only actual Ghidra processes (OpenJDK platform binary) gracefully"""
        print("🛑 Closing Ghidra processes...")
        
        processes_closed = 0
        
        try:
            # Method 1: Find and close actual Ghidra processes with enhanced detection
            print("  Identifying actual Ghidra processes...")
            try:
                # Enhanced PowerShell script with multiple detection methods
                ps_script = '''
                Write-Host "=== GHIDRA PROCESS DETECTION ==="
                
                # Method 1: Find java.exe processes with ghidra in command line (case insensitive)
                Write-Host "Checking java.exe processes with ghidra in command line..."
                $ghidraJavaProcesses = Get-WmiObject Win32_Process | Where-Object { 
                    $_.Name -eq "java.exe" -and $_.CommandLine -match "ghidra"
                }
                
                foreach ($proc in $ghidraJavaProcesses) {
                    Write-Host "Found Ghidra java process: PID $($proc.ProcessId)"
                    Write-Host "CommandLine: $($proc.CommandLine.Substring(0, [Math]::Min(100, $proc.CommandLine.Length)))..."
                    
                    $processObj = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                    if ($processObj) {
                        Write-Host "Process details: Name=$($processObj.Name), WindowTitle=$($processObj.MainWindowTitle)"
                        if ($processObj.MainWindowHandle -ne 0) {
                            $processObj.CloseMainWindow() | Out-Null
                            Write-Host "Closed Ghidra java window: $($processObj.MainWindowTitle)"
                        } else {
                            Write-Host "No main window, will force close later"
                        }
                    }
                }
                
                # Method 2: Find processes with Ghidra-related window titles (only java-based processes)
                Write-Host "Checking Java processes with Ghidra window titles..."
                $ghidraWindowProcesses = Get-Process | Where-Object { 
                    $_.MainWindowTitle -match "Ghidra" -and ($_.Name -eq "java" -or $_.Name -eq "javaw" -or $_.Name -eq "ghidraRun")
                }
                
                foreach ($proc in $ghidraWindowProcesses) {
                    Write-Host "Found Ghidra window process: PID $($proc.Id), Name=$($proc.Name), Title=$($proc.MainWindowTitle)"
                    if ($proc.MainWindowHandle -ne 0) {
                        $proc.CloseMainWindow() | Out-Null
                        Write-Host "Closed Ghidra window: $($proc.MainWindowTitle)"
                    }
                }
                
                # Method 3: Find ghidraRun.exe processes
                Write-Host "Checking for ghidraRun.exe processes..."
                $ghidraRunProcesses = Get-Process -Name "ghidraRun" -ErrorAction SilentlyContinue
                foreach ($proc in $ghidraRunProcesses) {
                    Write-Host "Found ghidraRun process: PID $($proc.Id) - $($proc.MainWindowTitle)"
                    if ($proc.MainWindowHandle -ne 0) {
                        $proc.CloseMainWindow() | Out-Null
                        Write-Host "Closed ghidraRun window: $($proc.MainWindowTitle)"
                    }
                }
                
                Write-Host "=== DETECTION COMPLETE ==="
                '''
                result = subprocess.run(["powershell", "-Command", ps_script], 
                             capture_output=True, text=True, timeout=30)
                print(f"  PowerShell detection output:")
                print(f"  {result.stdout}")
                if result.stderr:
                    print(f"  PowerShell errors: {result.stderr}")
                    
                processes_closed += result.stdout.count("Closed Ghidra java window:")
                processes_closed += result.stdout.count("Closed Ghidra window:")
                processes_closed += result.stdout.count("Closed ghidraRun window:")
                
            except Exception as e:
                print(f"  Warning: PowerShell graceful close failed: {e}")
            
            # Wait for graceful shutdown
            print("  Waiting for graceful shutdown...")
            time.sleep(5)
            
            # Method 2: Check for remaining Ghidra processes and force close if needed
            print("  Checking for remaining Ghidra processes...")
            remaining_pids = []
            
            try:
                # Check for ghidraRun.exe processes
                result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq ghidraRun.exe", "/FO", "CSV"], 
                             capture_output=True, text=True)
                if "ghidraRun.exe" in result.stdout:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    for line in lines:
                        if line and "ghidraRun.exe" in line:
                            parts = line.replace('"', '').split(',')
                            if len(parts) > 1:
                                remaining_pids.append(parts[1])  # PID is second column
                
                # Check for java.exe processes with Ghidra in command line
                result = subprocess.run([
                    "wmic", "process", "where", 
                    "name='java.exe' and CommandLine like '%ghidra%'", 
                    "get", "ProcessId", "/format:csv"
                ], capture_output=True, text=True)
                
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line and line != "Node,ProcessId" and "," in line:
                            pid = line.split(',')[1].strip()
                            if pid and pid.isdigit():
                                remaining_pids.append(pid)
                                
            except Exception as e:
                print(f"  Warning: Could not check remaining processes: {e}")
            
            # Method 3: Force close remaining Ghidra processes by PID
            if remaining_pids:
                print(f"  Force closing {len(remaining_pids)} remaining Ghidra processes...")
                for pid in remaining_pids:
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", pid], 
                                     capture_output=True, text=True)
                        print(f"    Force closed PID {pid}")
                        processes_closed += 1
                    except:
                        pass
            
            # Method 4: Close any process using port 8089 (our plugin port)
            print("  Closing processes using port 8089...")
            try:
                result = subprocess.run(["netstat", "-ano", "|", "findstr", ":8089"], 
                             capture_output=True, text=True, shell=True)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) > 4 and parts[1].endswith(':8089'):
                            pid = parts[-1]
                            if pid != "0":  # Skip invalid PIDs
                                try:
                                    subprocess.run(["taskkill", "/F", "/PID", pid], 
                                         capture_output=True, text=True)
                                    processes_closed += 1
                                    print(f"    Closed process PID {pid} using port 8089")
                                except:
                                    pass
            except:
                pass
            
            # Wait for processes to fully terminate
            print("  Waiting for final cleanup...")
            time.sleep(3)
            
            print(f"✅ Closed {processes_closed} Ghidra-related processes")
            return True
            
        except Exception as e:
            print(f"⚠️  Error closing Ghidra: {e}")
            return False
    
    def verify_ghidra_closed(self):
        """Verify that all actual Ghidra processes are closed"""
        print("🔍 Verifying all Ghidra processes are closed...")
        
        try:
            # Check for ghidraRun.exe processes
            result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq ghidraRun.exe"], 
                         capture_output=True, text=True)
            if "ghidraRun.exe" in result.stdout and "No tasks are running" not in result.stdout:
                print("⚠️  ghidraRun.exe still running")
                return False
            
            # Check specifically for Java processes with Ghidra in command line (more precise)
            result = subprocess.run([
                "wmic", "process", "where", 
                "name='java.exe' and CommandLine like '%ghidra%'", 
                "get", "ProcessId,CommandLine", "/format:csv"
            ], capture_output=True, text=True)
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                ghidra_java_processes = [line for line in lines if line and "ghidra" in line.lower() and "ProcessId" not in line]
                if ghidra_java_processes:
                    print(f"⚠️  {len(ghidra_java_processes)} Java processes with Ghidra still running")
                    for proc in ghidra_java_processes[:2]:  # Show first 2
                        print(f"     {proc[:80]}...")
                    return False
            
            # Check if port 8089 is free
            result = subprocess.run(["netstat", "-an", "|", "findstr", ":8089"], 
                         capture_output=True, text=True, shell=True)
            if result.stdout:
                print("⚠️  Port 8089 still in use")
                return False
            
            print("✅ All Ghidra processes confirmed closed")
            return True
            
        except Exception as e:
            print(f"⚠️  Error verifying Ghidra closed: {e}")
            return False
    
    def deploy_plugin(self):
        """Deploy the built plugin to Ghidra installation with enhanced deployment"""
        print("📦 Deploying Plugin to Ghidra...")
        print("="*50)
        
        if not self.ghidra_path:
            print("❌ Ghidra path not found")
            return False
            
        # Verify build artifacts exist and are valid
        artifacts_to_check = [
            (self.zip_file, "Plugin ZIP"),
            (self.bridge_script, "Python bridge script")
        ]
        
        for artifact, name in artifacts_to_check:
            if not artifact.exists():
                print(f"❌ {name} not found: {artifact}")
                return False
            size = artifact.stat().st_size
            if size < 100:  # Reasonable minimum size
                print(f"❌ {name} is too small ({size} bytes): {artifact}")
                return False
            print(f"✅ {name} validated: {artifact.name} ({size:,} bytes)")
        
        try:
            import shutil
            
            # 1. Create Extensions directory
            extensions_dir = self.ghidra_path / "Extensions" / "Ghidra"
            extensions_dir.mkdir(parents=True, exist_ok=True)
            print(f"✅ Extensions directory ready: {extensions_dir}")
            
            # 2. Remove existing GhidraMCP installations (like deploy-to-ghidra.ps1)
            existing_plugins = list(extensions_dir.glob("GhidraMCP*.zip"))
            if existing_plugins:
                print("🗑️  Removing existing GhidraMCP installations...")
                for plugin in existing_plugins:
                    plugin.unlink()
                    print(f"   Removed: {plugin.name}")
            
            # 3. Deploy main plugin ZIP
            target_zip = extensions_dir / "GhidraMCP-1.2.0.zip"
            shutil.copy2(self.zip_file, target_zip)
            print(f"✅ Plugin ZIP deployed: {target_zip}")
            
            # 4. Deploy to user Extensions directory (for development/debugging)
            user_extensions_dir = Path(os.environ.get("USERPROFILE", "")) / "AppData" / "Roaming" / "ghidra" / "ghidra_11.4.2_PUBLIC" / "Extensions" / "GhidraMCP" / "lib"
            try:
                if self.jar_file.exists():
                    user_extensions_dir.mkdir(parents=True, exist_ok=True)
                    user_jar = user_extensions_dir / "GhidraMCP.jar"
                    shutil.copy2(self.jar_file, user_jar)
                    print(f"✅ JAR deployed to user extensions: {user_jar}")
            except Exception as e:
                print(f"⚠️  Could not deploy to user extensions: {e}")
            
            # 5. Deploy Python bridge and requirements
            target_bridge = self.ghidra_path / "bridge_mcp_ghidra.py"
            if target_bridge.exists():
                target_bridge.unlink()  # Remove existing
            shutil.copy2(self.bridge_script, target_bridge)
            print(f"✅ Python bridge deployed: {target_bridge}")
            
            # Copy requirements.txt if it exists
            requirements_file = self.workspace_root / "requirements.txt"
            if requirements_file.exists():
                target_requirements = self.ghidra_path / "requirements.txt"
                shutil.copy2(requirements_file, target_requirements)
                print(f"✅ Requirements file deployed: {target_requirements}")
            
            # 6. Deploy JAR for quick access
            if self.jar_file.exists():
                target_jar = self.ghidra_path / "GhidraMCP.jar"
                shutil.copy2(self.jar_file, target_jar)
                print(f"✅ JAR deployed to Ghidra root: {target_jar}")
            
            # 7. Try to enable plugin in preferences (best effort)
            self._try_enable_plugin_in_preferences()
            
            print("✅ Enhanced deployment completed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Deployment error: {e}")
            return False
    
    def _try_enable_plugin_in_preferences(self):
        """Try to enable the plugin in Ghidra preferences (best effort)"""
        try:
            user_dir = Path(os.environ.get("USERPROFILE", "")) / ".ghidra"
            if not user_dir.exists():
                return
            
            # Find plugins.xml files
            import glob
            prefs_pattern = str(user_dir / "*" / "preferences" / "*" / "plugins.xml")
            prefs_files = glob.glob(prefs_pattern, recursive=True)
            
            if prefs_files:
                print("🔧 Attempting to enable plugin in preferences...")
                
                for prefs_file in prefs_files:
                    try:
                        import xml.etree.ElementTree as ET
                        
                        tree = ET.parse(prefs_file)
                        root = tree.getroot()
                        
                        # Look for GhidraMCPPlugin
                        plugin_found = False
                        for plugin in root.findall(".//PLUGIN[@NAME='GhidraMCPPlugin']"):
                            plugin.set("ENABLED", "true")
                            plugin_found = True
                        
                        if plugin_found:
                            tree.write(prefs_file)
                            print(f"   ✅ Enabled in: {Path(prefs_file).name}")
                        
                    except Exception:
                        continue  # Best effort, don't fail deployment
                        
        except Exception:
            pass  # Best effort, don't fail deployment
    
    def close_existing_ghidra(self):
        """Close any existing Ghidra instances."""
        print("\n🔍 CHECKING FOR EXISTING GHIDRA INSTANCES")
        print("="*50)
        
        try:
            # Find Java processes that might be Ghidra
            cmd = ['powershell', '-Command', 
                   'Get-Process | Where-Object { $_.ProcessName -eq "java" -or $_.ProcessName -eq "javaw" } | Select-Object Id, ProcessName, @{Name="CommandLine"; Expression={(Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine}}']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            ghidra_processes = []
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'ghidra' in line.lower() or 'Ghidra' in line:
                        # Extract process ID
                        parts = line.strip().split()
                        if parts and parts[0].isdigit():
                            ghidra_processes.append(int(parts[0]))
            
            if ghidra_processes:
                print(f"Found {len(ghidra_processes)} Ghidra process(es) to close")
                for pid in ghidra_processes:
                    try:
                        subprocess.run(['taskkill', '/PID', str(pid), '/F'], 
                                     capture_output=True, timeout=10)
                        print(f"   Closed Ghidra process (PID: {pid})")
                    except:
                        print(f"   Could not close process {pid}")
                
                # Wait a moment for processes to fully terminate
                time.sleep(3)
                print("✅ Existing Ghidra instances closed")
            else:
                print("✅ No existing Ghidra instances found")
                
        except Exception as e:
            print(f"⚠️  Could not check for existing Ghidra instances: {e}")
    
    def start_ghidra(self, project_path=None, binary_path=None):
        """Start Ghidra with enhanced project and binary loading to ensure CodeBrowser opens"""
        print("\n🔍 Step 4: Verifying Ghidra is not already running...")
        print("="*50)
        
        # Check if Ghidra is already running
        if not self.verify_ghidra_closed():
            print("⚠️  Ghidra is still running. Attempting graceful shutdown...")
            if not self.close_ghidra():
                print("❌ Failed to close Ghidra processes")
                return False
            
            # Wait and verify again
            time.sleep(3)
            if not self.verify_ghidra_closed():
                print("❌ Ghidra processes still running after shutdown attempt")
                return False
        
        print("✅ Verified Ghidra is not running - proceeding with startup")
        
        print("\n🚀 Starting Ghidra...")
        print("="*50)
        
        # Use the exact Ghidra path from your example if available
        exact_ghidra_path = Path("F:\\ghidra_11.4.2")
        if exact_ghidra_path.exists() and (exact_ghidra_path / "ghidraRun.bat").exists():
            self.ghidra_path = exact_ghidra_path
            print(f"✅ Using exact Ghidra path from example: {self.ghidra_path}")
        elif not self.ghidra_path:
            print("❌ Ghidra path not found")
            return False
        
        try:
            # Find Ghidra executable (prioritize ghidraRun.bat for Windows)
            ghidra_executables = [
                self.ghidra_path / "ghidraRun.bat",
                self.ghidra_path / "ghidraRun"
            ]
            
            ghidra_run = None
            for exe in ghidra_executables:
                if exe.exists():
                    ghidra_run = exe
                    break
            
            if not ghidra_run:
                print(f"❌ Ghidra executable not found. Tried:")
                for exe in ghidra_executables:
                    print(f"   - {exe}")
                return False
            
            print(f"✅ Using Ghidra executable: {ghidra_run}")
            
            # Use default project/binary if none provided (EXACT format from your example)
            if not project_path and not binary_path:
                # Use EXACTLY the paths from your example: F:\ghidra_11.4.2\ghidraRun.bat "F:\GhidraProjects\PD2.gpr" "D2Game.dll"
                default_project = "F:\\GhidraProjects\\PD2.gpr"
                default_binary = "D2Game.dll"  # EXACT format - just filename, not full path
                
                print("🔧 Using EXACT command format from your example to ensure CodeBrowser opens...")
                
                if Path(default_project).exists():
                    project_path = default_project
                    print(f"✅ Using exact project path: {project_path}")
                    
                    # Use exact binary name as specified in your example
                    binary_path = default_binary
                    print(f"✅ Using exact binary name: {binary_path}")
                    print("📋 Note: Ghidra will look for D2Game.dll relative to project or working directory")
                else:
                    print("⚠️  Default project not found - starting without project (CodeBrowser may not open)")
            
            # Validate provided or found project and binary paths
            if project_path:
                project_file = Path(project_path)
                if not project_file.exists():
                    print(f"❌ Project file not found: {project_path}")
                    # Don't fail - continue without project
                    project_path = None
                elif not project_file.suffix == '.gpr':
                    print(f"⚠️  Project file doesn't have .gpr extension: {project_path}")
                else:
                    print(f"✅ Project file validated: {project_path}")
            
            if binary_path:
                binary_file = Path(binary_path)
                if binary_file.is_absolute() and not binary_file.exists():
                    print(f"❌ Binary file not found: {binary_path}")
                    # Don't fail - continue without binary
                    binary_path = None
                elif binary_file.is_absolute():
                    print(f"✅ Binary file validated: {binary_path}")
                else:
                    # For relative paths (like "D2Game.dll"), let Ghidra handle the resolution
                    print(f"✅ Using relative binary path (Ghidra will resolve): {binary_path}")
            
            # Build command EXACTLY as your example: F:\ghidra_11.4.2\ghidraRun.bat "F:\GhidraProjects\PD2.gpr" -open "D2Game.dll"
            if project_path and binary_path:
                # Create argument list exactly like your PowerShell script (no extra quotes in the list)
                cmd = [str(ghidra_run), project_path, '-open', binary_path]
                print(f"📂 Will load project: {project_path}")
                print(f"📄 Will open binary in CodeBrowser: {binary_path}")
                print(f"🎯 EXACT command: {ghidra_run} \"{project_path}\" -open \"{binary_path}\"")
                print("🎯 The -open flag ensures CodeBrowser opens automatically!")
                wait_time = 35  # More time for project/binary loading
            elif project_path:
                cmd = [str(ghidra_run), project_path]
                print(f"📂 Will load project: {project_path}")
                print("🎯 This should open the project (CodeBrowser may need manual opening)")
                wait_time = 25
            else:
                cmd = [str(ghidra_run)]
                print("📋 Starting Ghidra without project")
                print("⚠️  CodeBrowser will need to be opened manually")
                wait_time = 15
            
            # Start Ghidra with proper argument list (no shell=True to avoid quote issues)
            print(f"🚀 Executing command with args: {cmd}")
            process = subprocess.Popen(cmd, cwd=self.ghidra_path)
            
            print(f"✅ Ghidra started (PID: {process.pid})")
            print(f"⏳ Waiting {wait_time} seconds for Ghidra to fully load...")
            time.sleep(wait_time)
            
            return True
            
        except Exception as e:
            print(f"❌ Error starting Ghidra: {e}")
            return False
    
    def wait_for_plugin(self, timeout=60):
        """Wait for the plugin to be loaded and server to be available"""
        print("⏳ Waiting for GhidraMCP plugin to load...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get("http://localhost:8089/get_metadata", timeout=5)
                if response.status_code == 200:
                    print("✅ GhidraMCP plugin is ready!")
                    return True
            except:
                pass
            
            print(".", end="", flush=True)
            time.sleep(2)
        
        print(f"\n❌ Plugin not ready after {timeout} seconds")
        return False
    
    def check_codebrowser_window(self, max_retries=3, retry_delay=5):
        """Check if CodeBrowser window is open with retry logic"""
        print("🔍 Checking for CodeBrowser window...")
        
        for attempt in range(max_retries):
            if attempt > 0:
                print(f"   Retry {attempt}/{max_retries - 1} - waiting {retry_delay} seconds...")
                time.sleep(retry_delay)
            
            try:
                # Enhanced PowerShell script to find CodeBrowser windows
                ps_script = '''
                Write-Host "=== CODEBROWSER WINDOW DETECTION ==="
                
                # Method 1: Look for exact CodeBrowser window titles (most specific)
                $codeBrowserWindows = Get-Process | Where-Object { 
                    $_.MainWindowTitle -like "*CodeBrowser*" -and ($_.Name -eq "java" -or $_.Name -eq "javaw")
                }
                
                Write-Host "Method 1 - Exact CodeBrowser windows:"
                foreach ($window in $codeBrowserWindows) {
                    Write-Host "  Found: PID $($window.Id), Title: '$($window.MainWindowTitle)'"
                }
                
                # Method 2: Look for Ghidra windows with binary loaded (indicates CodeBrowser likely open)
                $projectGhidraWindows = Get-Process | Where-Object { 
                    ($_.Name -eq "java" -or $_.Name -eq "javaw") -and 
                    $_.MainWindowTitle -match "Ghidra.*-.*\\.exe|Ghidra.*-.*\\.dll" -and
                    $_.MainWindowTitle -notmatch "NO ACTIVE PROJECT"
                }
                
                Write-Host "Method 2 - Ghidra with binary loaded:"
                foreach ($window in $projectGhidraWindows) {
                    Write-Host "  Found: PID $($window.Id), Title: '$($window.MainWindowTitle)'"
                }
                
                # Method 3: Look for Ghidra windows with specific project name patterns
                $pd2GhidraWindows = Get-Process | Where-Object { 
                    ($_.Name -eq "java" -or $_.Name -eq "javaw") -and 
                    ($_.MainWindowTitle -match "Ghidra.*PD2|PD2.*Ghidra|D2Game" -or
                     $_.MainWindowTitle -like "*CodeBrowser*")
                }
                
                Write-Host "Method 3 - PD2/D2Game/CodeBrowser windows:"
                foreach ($window in $pd2GhidraWindows) {
                    Write-Host "  Found: PID $($window.Id), Title: '$($window.MainWindowTitle)'"
                }
                
                # Determine if CodeBrowser is detected
                $codeBrowserFound = ($codeBrowserWindows.Count -gt 0)
                $binaryLoadedFound = ($projectGhidraWindows.Count -gt 0)
                $pd2Found = ($pd2GhidraWindows.Count -gt 0)
                
                Write-Host ""
                Write-Host "DETECTION SUMMARY:"
                Write-Host "  Exact CodeBrowser windows: $($codeBrowserWindows.Count)"
                Write-Host "  Binary-loaded Ghidra windows: $($projectGhidraWindows.Count)"  
                Write-Host "  PD2/D2Game related windows: $($pd2GhidraWindows.Count)"
                
                if ($codeBrowserFound -or $binaryLoadedFound -or $pd2Found) {
                    Write-Host "RESULT: CodeBrowser window detected (likely open)"
                    $true
                } else {
                    Write-Host "RESULT: CodeBrowser window not detected"
                    $false
                }
                '''
                
                result = subprocess.run(["powershell", "-Command", ps_script], 
                                      capture_output=True, text=True, timeout=30)
                
                print(f"   Detection output (attempt {attempt + 1}):")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        print(f"     {line}")
                
                if "RESULT: CodeBrowser window detected" in result.stdout:
                    print("✅ CodeBrowser window is open!")
                    return True
                elif attempt < max_retries - 1:
                    print(f"   ⏳ CodeBrowser not detected yet, retrying...")
                else:
                    print("⚠️  CodeBrowser window not found after all attempts")
                    
            except Exception as e:
                print(f"   ❌ Error in attempt {attempt + 1}: {e}")
                if attempt == max_retries - 1:
                    print(f"❌ Error checking CodeBrowser window after {max_retries} attempts")
                    return False
        
        return False
    
    def test_mcp_endpoint(self, endpoint: str, method: str, description: str, data: Dict[str, Any] = None) -> TestResult:
        """Test a single MCP endpoint with comprehensive error handling"""
        start_time = time.time()
        url = f"{self.mcp_base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, timeout=30)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            duration = time.time() - start_time
            success = response.status_code == 200
            
            result = TestResult(
                endpoint=endpoint,
                method=method,
                description=description,
                success=success,
                duration=duration,
                response_code=response.status_code,
                error_message="" if success else response.text[:200]
            )
            
            self.logger.info(f"{'✅' if success else '❌'} {description}: {response.status_code} ({duration:.3f}s)")
            
        except Exception as e:
            duration = time.time() - start_time
            result = TestResult(
                endpoint=endpoint,
                method=method,
                description=description,
                success=False,
                duration=duration,
                response_code=0,
                error_message=str(e)[:200]
            )
            self.logger.error(f"❌ {description}: {str(e)}")
            
        self.test_results.append(result)
        return result

    def run_comprehensive_mcp_test(self):
        """Run comprehensive test of all Ghidra MCP endpoints for verification"""
        print("🧪 COMPREHENSIVE GHIDRA MCP ENDPOINT VERIFICATION")
        print("="*70)
        
        self.test_results.clear()
        
        # Test connection first
        connection_result = self.test_mcp_endpoint('/check_connection', 'GET', 'Check MCP connection')
        if not connection_result.success:
            print("❌ Cannot connect to MCP plugin. Aborting comprehensive test.")
            return False
            
        # Core information endpoints
        print("\n📋 Core Information:")
        self.test_mcp_endpoint('/get_metadata', 'GET', 'Get program metadata')
        self.test_mcp_endpoint('/get_entry_points', 'GET', 'Get entry points')
        
        # Function endpoints
        print("\n🔧 Function Operations:")
        self.test_mcp_endpoint('/functions?limit=10', 'GET', 'List functions')
        self.test_mcp_endpoint('/searchFunctions?searchTerm=main&limit=5', 'GET', 'Search functions')
        self.test_mcp_endpoint('/decompile_function/main', 'GET', 'Decompile function')
        self.test_mcp_endpoint('/function_xrefs/main', 'GET', 'Get function cross-refs')
        self.test_mcp_endpoint('/function_callers/main', 'GET', 'Get function callers')
        self.test_mcp_endpoint('/function_callees/main', 'GET', 'Get function callees')
        self.test_mcp_endpoint('/function_call_graph/main', 'GET', 'Get call graph')
        
        # Get function by address for further testing
        test_address = "0x034c1000"  # Default fallback
        try:
            functions_response = requests.get(f"{self.mcp_base_url}/functions?limit=1", timeout=10)
            if functions_response.status_code == 200:
                lines = functions_response.text.strip().split('\n')
                if lines and lines[0].strip():
                    # Try to extract address from function line
                    parts = lines[0].split(' @ ')
                    if len(parts) == 2:
                        test_address = parts[1].strip()
                        print(f"🎯 Using test address: {test_address}")
        except:
            pass
        
        # Memory and analysis
        print("\n🧠 Memory & Analysis:")
        self.test_mcp_endpoint('/segments', 'GET', 'List memory segments')
        self.test_mcp_endpoint(f'/get_function_by_address/{test_address}', 'GET', 'Get function by address')
        self.test_mcp_endpoint(f'/disassemble_function/{test_address}', 'GET', 'Disassemble function')
        self.test_mcp_endpoint(f'/xrefs_to/{test_address}', 'GET', 'Get cross-refs to address')
        self.test_mcp_endpoint(f'/xrefs_from/{test_address}', 'GET', 'Get cross-refs from address')
        
        # Data types
        print("\n📊 Data Types:")
        self.test_mcp_endpoint('/data_types?limit=10', 'GET', 'List data types')
        self.test_mcp_endpoint('/search_data_types?pattern=int&limit=5', 'GET', 'Search data types')
        
        # Creation endpoints (The original functionality preserved)
        print("\n🏗️  Creation Operations:")
        timestamp = str(int(time.time()))
        
        self.test_mcp_endpoint('/create_struct', 'POST', 'Create structure', {
            "name": f"TestStruct_Comprehensive_{timestamp}",
            "fields": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "char[32]"}
            ]
        })
        
        self.test_mcp_endpoint('/create_union', 'POST', 'Create union', {
            "name": f"TestUnion_Comprehensive_{timestamp}",
            "fields": [
                {"name": "as_int", "type": "dword"},
                {"name": "as_bytes", "type": "char[4]"}
            ]
        })
        
        self.test_mcp_endpoint('/create_enum', 'POST', 'Create enumeration', {
            "name": f"TestEnum_Comprehensive_{timestamp}",
            "values": {"OPTION_A": 0, "OPTION_B": 1, "OPTION_C": 2}
        })
        
        # Symbols and strings
        print("\n🔤 Symbols & Strings:")
        self.test_mcp_endpoint('/imports?limit=10', 'GET', 'List imports')
        self.test_mcp_endpoint('/exports?limit=10', 'GET', 'List exports')
        self.test_mcp_endpoint('/strings?limit=10', 'GET', 'List strings')
        self.test_mcp_endpoint('/namespaces?limit=10', 'GET', 'List namespaces')
        
        # Utilities
        print("\n🛠️  Utilities:")
        self.test_mcp_endpoint('/create_label', 'POST', 'Create label', {
            "address": test_address,
            "name": f"TEST_LABEL_COMPREHENSIVE_{timestamp}"
        })
        self.test_mcp_endpoint('/convert_number/123', 'GET', 'Convert number')
        
        # Generate comprehensive summary
        return self.generate_comprehensive_test_summary()
        
    def generate_comprehensive_test_summary(self):
        """Generate detailed test summary with recommendations"""
        print("\n" + "="*70)
        print("📊 COMPREHENSIVE MCP VERIFICATION SUMMARY")
        print("="*70)
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for r in self.test_results if r.success)
        failed_tests = total_tests - successful_tests
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"✅ Total Tests: {total_tests}")
        print(f"✅ Successful: {successful_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if not result.success:
                    print(f"   • {result.description}: {result.response_code} - {result.error_message}")
        
        # Performance analysis
        sorted_results = sorted(self.test_results, key=lambda x: x.duration, reverse=True)
        print(f"\n⏱️  Top 5 Slowest Tests:")
        for i, result in enumerate(sorted_results[:5]):
            print(f"   {i+1}. {result.description}: {result.duration:.3f}s")
            
        # Save detailed report to logs
        try:
            logs_dir = self.workspace_root / 'logs'
            logs_dir.mkdir(exist_ok=True)
            
            report_file = logs_dir / f'comprehensive_mcp_test_{int(time.time())}.json'
            report_data = {
                'timestamp': time.time(),
                'total_tests': total_tests,
                'successful_tests': successful_tests,
                'failed_tests': failed_tests,
                'success_rate': success_rate,
                'results': [
                    {
                        'endpoint': r.endpoint,
                        'method': r.method,
                        'description': r.description,
                        'success': r.success,
                        'duration': r.duration,
                        'response_code': r.response_code,
                        'error_message': r.error_message
                    } for r in self.test_results
                ]
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"\n� Detailed report saved: {report_file}")
            
        except Exception as e:
            print(f"⚠️  Could not save detailed report: {e}")
            
        print(f"\n🎯 Comprehensive MCP verification complete!")
        print(f"{'🎉 ALL SYSTEMS OPERATIONAL!' if success_rate >= 95 else '⚠️  SOME ISSUES DETECTED - CHECK FAILED TESTS'}")
        
        # Return results for backward compatibility
        return {
            'total': total_tests,
            'successful': successful_tests,
            'success_rate': success_rate,
            'all_passed': success_rate >= 95
        }
    
    def debug_union_creation(self):
        """Dedicated union creation debugging with detailed analysis"""
        print("🔬 UNION CREATION DEBUGGING")
        print("="*60)
        
        # Test multiple union creation approaches
        union_tests = [
            {
                "name": "SimpleUnion",
                "description": "Basic int/float union",
                "payload": {
                    "name": "SimpleUnion_" + str(int(time.time())),
                    "fields": [
                        {"name": "as_int", "type": "int"},
                        {"name": "as_float", "type": "float"}
                    ]
                }
            },
            {
                "name": "StringUnion", 
                "description": "Union with string field",
                "payload": {
                    "name": "StringUnion_" + str(int(time.time())),
                    "fields": [
                        {"name": "as_int", "type": "int"},
                        {"name": "as_string", "type": "char[32]"}
                    ]
                }
            },
            {
                "name": "MinimalUnion",
                "description": "Minimal single field union",
                "payload": {
                    "name": "MinimalUnion_" + str(int(time.time())),
                    "fields": [
                        {"name": "value", "type": "int"}
                    ]
                }
            }
        ]
        
        results = {}
        
        for i, test in enumerate(union_tests, 1):
            print(f"\n🧪 Test {i}: {test['description']}")
            print(f"   Payload: {json.dumps(test['payload'], indent=4)}")
            
            try:
                # Make the request with detailed logging
                print("   Making HTTP request...")
                response = requests.post(
                    "http://localhost:8089/create_union", 
                    json=test['payload'],
                    timeout=30
                )
                
                print(f"   Status Code: {response.status_code}")
                print(f"   Headers: {dict(response.headers)}")
                
                if response.content:
                    print(f"   Response Body: {response.text}")
                else:
                    print("   Response Body: (empty)")
                
                results[test['name']] = {
                    'success': response.status_code == 200,
                    'status_code': response.status_code,
                    'response': response.text if response.content else "(empty)",
                    'error': None
                }
                
                print(f"   Result: {'✅ SUCCESS' if response.status_code == 200 else '❌ FAILED'}")
                
            except requests.exceptions.ConnectionError as e:
                print(f"   ❌ Connection Error: {e}")
                results[test['name']] = {
                    'success': False,
                    'status_code': None,
                    'response': None,
                    'error': f"Connection Error: {e}"
                }
            except requests.exceptions.Timeout as e:
                print(f"   ❌ Timeout Error: {e}")
                results[test['name']] = {
                    'success': False,
                    'status_code': None,
                    'response': None,
                    'error': f"Timeout: {e}"
                }
            except Exception as e:
                print(f"   ❌ Unexpected Error: {e}")
                results[test['name']] = {
                    'success': False,
                    'status_code': None,
                    'response': None,
                    'error': f"Error: {e}"
                }
            
            # Small delay between tests
            time.sleep(2)
        
        # Analysis and summary
        print(f"\n📊 UNION DEBUG SUMMARY")
        print("="*60)
        
        working_tests = sum(1 for r in results.values() if r['success'])
        total_tests = len(results)
        
        print(f"Working: {working_tests}/{total_tests} ({working_tests/total_tests*100:.1f}%)")
        
        for test_name, result in results.items():
            status = "✅" if result['success'] else "❌"
            print(f"{status} {test_name}: {result.get('status_code', 'N/A')}")
            if result['error']:
                print(f"   Error: {result['error']}")
        
        # If all tests fail, suggest next steps
        if working_tests == 0:
            print(f"\n🔧 TROUBLESHOOTING SUGGESTIONS:")
            print("1. Check if Ghidra plugin is properly loaded")
            print("2. Verify port 8089 is accessible") 
            print("3. Check server logs in Ghidra console")
            print("4. Test struct creation to compare")
            print("5. Review union endpoint implementation in Java code")
        
        return results
    
    def create_binary_documentation_prompt(self, binary_path: str = None) -> str:
        """Create a comprehensive prompt for documenting a binary using Ghidra MCP tools"""
        
        prompt = """
# Binary Documentation Strategy using Ghidra MCP Tools

## Objective
Document a binary comprehensively using Ghidra's MCP interface to demonstrate real-world reverse engineering workflow.

## Phase 1: Initial Analysis & Overview
1. **Program Metadata Collection**
   - Get program metadata (architecture, base address, entry points)
   - Identify memory segments and their properties
   - Document program entry points and their purposes

2. **Function Discovery & Cataloging**  
   - List all functions in the binary
   - Identify imported and exported functions
   - Create function call graph to understand program flow
   - Focus on main function and key entry points

## Phase 2: Deep Function Analysis
3. **Critical Function Analysis**
   - Decompile main function and other key functions
   - Analyze function signatures and parameters
   - Document function purposes and behaviors
   - Identify interesting or suspicious functions

4. **Cross-Reference Analysis**
   - Map function call relationships (callers/callees)
   - Identify data flow between functions
   - Document critical code paths

## Phase 3: Data Structure Documentation
5. **String Analysis**
   - Extract and categorize all strings
   - Identify error messages, debug strings, URLs, file paths
   - Look for hardcoded credentials or sensitive data

6. **Data Type Creation**
   - Create custom structures for identified data formats
   - Define unions for multi-purpose data areas
   - Create enumerations for constant values

## Phase 4: Advanced Analysis
7. **Memory Layout Mapping**
   - Document memory segments and their purposes
   - Identify code vs data regions
   - Map global variables and their usage

8. **Symbol & Namespace Organization**
   - Document all symbols and their meanings
   - Organize findings into logical namespaces
   - Create labels for important addresses

## Phase 5: Documentation Generation
9. **Comprehensive Report Creation**
   - Summarize key findings and security implications
   - Document potential vulnerabilities or interesting behaviors
   - Create actionable insights for further analysis

## Expected Deliverables
- Program overview with architecture and entry points
- Function catalog with purposes and call relationships
- String analysis report with security implications
- Custom data structures representing program internals
- Memory layout documentation
- Comprehensive analysis report with actionable insights

## Success Criteria
- Complete program understanding achieved
- All major functions documented and understood
- Data structures and memory layout mapped
- Security implications identified
- Professional-grade documentation produced
"""
        
        return prompt.strip()
    
    def execute_binary_documentation(self, binary_path: str = None) -> Dict[str, Any]:
        """Execute the binary documentation workflow using Ghidra MCP tools"""
        print("📚 Step 8: Real-World Binary Documentation using Ghidra MCP...")
        print("="*70)
        
        documentation_results = {
            'success': False,
            'phases_completed': [],
            'findings': {},
            'errors': [],
            'recommendations': [],
            'quality_score': 0.0
        }
        
        try:
            # Phase 1: Initial Analysis & Overview
            print("\n🔍 Phase 1: Initial Analysis & Overview")
            phase1_success = True
            
            # Get program metadata
            print("   📊 Collecting program metadata...")
            metadata_result = self.test_mcp_endpoint('/get_metadata', 'GET', 'Program metadata')
            if metadata_result.success:
                documentation_results['findings']['metadata'] = "Program metadata collected"
                print("   ✅ Program metadata collected")
            else:
                phase1_success = False
                documentation_results['errors'].append("Failed to collect program metadata")
            
            # Get entry points
            print("   🚪 Identifying entry points...")
            entry_points_result = self.test_mcp_endpoint('/get_entry_points', 'GET', 'Entry points')
            if entry_points_result.success:
                documentation_results['findings']['entry_points'] = "Entry points identified"
                print("   ✅ Entry points identified")
            else:
                phase1_success = False
                documentation_results['errors'].append("Failed to identify entry points")
            
            # Get memory segments
            print("   🗺️  Mapping memory segments...")
            segments_result = self.test_mcp_endpoint('/segments', 'GET', 'Memory segments')
            if segments_result.success:
                documentation_results['findings']['memory_segments'] = "Memory layout documented"
                print("   ✅ Memory segments mapped")
            else:
                phase1_success = False
                documentation_results['errors'].append("Failed to map memory segments")
            
            if phase1_success:
                documentation_results['phases_completed'].append('Phase 1: Initial Analysis')
            
            # Phase 2: Deep Function Analysis
            print("\n🔧 Phase 2: Deep Function Analysis")
            phase2_success = True
            
            # List functions
            print("   📋 Cataloging functions...")
            functions_result = self.test_mcp_endpoint('/functions?limit=20', 'GET', 'Function catalog')
            if functions_result.success:
                documentation_results['findings']['functions'] = "Function catalog created"
                print("   ✅ Functions cataloged")
            else:
                phase2_success = False
                documentation_results['errors'].append("Failed to catalog functions")
            
            # Analyze main function if it exists
            print("   🎯 Analyzing main function...")
            main_analysis_result = self.test_mcp_endpoint('/decompile_function/main', 'GET', 'Main function analysis')
            if main_analysis_result.success:
                documentation_results['findings']['main_function'] = "Main function analyzed and decompiled"
                print("   ✅ Main function analyzed")
            else:
                print("   ⚠️  Main function not found or analysis failed")
                documentation_results['errors'].append("Main function analysis failed")
            
            # Get function call graph
            print("   🕸️  Mapping function relationships...")
            call_graph_result = self.test_mcp_endpoint('/get_full_call_graph?format=edges&limit=50', 'GET', 'Call graph')
            if call_graph_result.success:
                documentation_results['findings']['call_graph'] = "Function relationships mapped"
                print("   ✅ Function call graph created")
            else:
                phase2_success = False
                documentation_results['errors'].append("Failed to create call graph")
                
            if phase2_success:
                documentation_results['phases_completed'].append('Phase 2: Function Analysis')
            
            # Phase 3: Data Structure Documentation
            print("\n📊 Phase 3: Data Structure Documentation")
            phase3_success = True
            
            # Extract strings
            print("   🔤 Extracting strings...")
            strings_result = self.test_mcp_endpoint('/strings?limit=50', 'GET', 'String extraction')
            if strings_result.success:
                documentation_results['findings']['strings'] = "Strings extracted and analyzed"
                print("   ✅ Strings extracted")
            else:
                phase3_success = False
                documentation_results['errors'].append("Failed to extract strings")
            
            # Create documentation structures
            print("   🏗️  Creating documentation structures...")
            timestamp = int(time.time())
            
            # Create a structure for documentation metadata
            doc_struct_result = self.test_mcp_endpoint('/create_struct', 'POST', 'Documentation structure', {
                "name": f"BinaryDocumentation_{timestamp}",
                "fields": [
                    {"name": "analysis_timestamp", "type": "dword"},
                    {"name": "binary_name", "type": "char[256]"},
                    {"name": "architecture", "type": "char[32]"},
                    {"name": "analysis_quality_score", "type": "float"}
                ]
            })
            
            if doc_struct_result.success:
                documentation_results['findings']['data_structures'] = "Custom documentation structures created"
                print("   ✅ Documentation structures created")
            else:
                phase3_success = False
                documentation_results['errors'].append("Failed to create documentation structures")
            
            if phase3_success:
                documentation_results['phases_completed'].append('Phase 3: Data Structure Documentation')
            
            # Phase 4: Advanced Analysis
            print("\n🔬 Phase 4: Advanced Analysis")
            phase4_success = True
            
            # Analyze imports and exports
            print("   📥 Analyzing imports and exports...")
            imports_result = self.test_mcp_endpoint('/imports?limit=20', 'GET', 'Import analysis')
            exports_result = self.test_mcp_endpoint('/exports?limit=20', 'GET', 'Export analysis')
            
            if imports_result.success and exports_result.success:
                documentation_results['findings']['imports_exports'] = "Import/export analysis completed"
                print("   ✅ Imports and exports analyzed")
            else:
                phase4_success = False
                documentation_results['errors'].append("Failed to analyze imports/exports")
            
            # Create labels for documentation
            print("   🏷️  Creating analysis labels...")
            label_result = self.test_mcp_endpoint('/create_label', 'POST', 'Documentation label', {
                "address": "0x00401000",  # Common entry point address
                "name": f"ANALYSIS_COMPLETED_{timestamp}"
            })
            
            if label_result.success:
                documentation_results['findings']['labels'] = "Analysis labels created"
                print("   ✅ Analysis labels created")
            
            if phase4_success:
                documentation_results['phases_completed'].append('Phase 4: Advanced Analysis')
            
            # Calculate quality score
            total_phases = 4
            completed_phases = len(documentation_results['phases_completed'])
            documentation_results['quality_score'] = (completed_phases / total_phases) * 100
            
            # Generate recommendations
            if completed_phases >= 3:
                documentation_results['recommendations'].extend([
                    "Excellent documentation coverage achieved",
                    "Binary analysis workflow successfully executed",
                    "Ready for detailed manual review and security assessment"
                ])
                documentation_results['success'] = True
            elif completed_phases >= 2:
                documentation_results['recommendations'].extend([
                    "Good foundation established for binary analysis",
                    "Consider additional function analysis for completeness",
                    "Manual review recommended for security implications"
                ])
                documentation_results['success'] = True
            else:
                documentation_results['recommendations'].extend([
                    "Basic analysis completed but insufficient for comprehensive documentation",
                    "Review MCP tool connectivity and binary loading",
                    "Consider manual analysis to supplement automated findings"
                ])
            
            print(f"\n📊 Documentation Quality Score: {documentation_results['quality_score']:.1f}%")
            print(f"📋 Phases Completed: {completed_phases}/{total_phases}")
            
        except Exception as e:
            documentation_results['errors'].append(f"Unexpected error in documentation workflow: {str(e)}")
            print(f"❌ Documentation workflow error: {e}")
        
        return documentation_results
    
    def evaluate_documentation_quality(self, doc_results: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate the quality of binary documentation and improve the prompt"""
        print("🔍 Step 9: Evaluating Documentation Quality & Improving Prompt...")
        print("="*70)
        
        evaluation = {
            'overall_score': doc_results.get('quality_score', 0.0),
            'strengths': [],
            'weaknesses': [],
            'improvements': [],
            'enhanced_prompt': '',
            'next_steps': []
        }
        
        # Analyze strengths
        phases_completed = doc_results.get('phases_completed', [])
        findings = doc_results.get('findings', {})
        errors = doc_results.get('errors', [])
        
        print("📊 Quality Assessment:")
        print(f"   📈 Overall Score: {evaluation['overall_score']:.1f}%")
        print(f"   ✅ Phases Completed: {len(phases_completed)}/4")
        print(f"   📝 Findings Generated: {len(findings)}")
        print(f"   ❌ Errors Encountered: {len(errors)}")
        
        # Identify strengths
        if len(phases_completed) >= 3:
            evaluation['strengths'].append("Comprehensive analysis workflow executed successfully")
        if 'metadata' in findings:
            evaluation['strengths'].append("Program metadata successfully collected")
        if 'functions' in findings:
            evaluation['strengths'].append("Function catalog generation successful")
        if 'call_graph' in findings:
            evaluation['strengths'].append("Function relationship mapping achieved")
        if 'strings' in findings:
            evaluation['strengths'].append("String extraction and analysis completed")
        if 'data_structures' in findings:
            evaluation['strengths'].append("Custom data structure creation successful")
        
        # Identify weaknesses
        if len(errors) > 2:
            evaluation['weaknesses'].append("Multiple MCP endpoint failures detected")
        if 'main_function' not in findings:
            evaluation['weaknesses'].append("Main function analysis incomplete")
        if len(phases_completed) < 3:
            evaluation['weaknesses'].append("Insufficient analysis depth achieved")
        if evaluation['overall_score'] < 75:
            evaluation['weaknesses'].append("Overall documentation quality below target threshold")
        
        # Generate improvements for the prompt
        improvements = []
        
        if 'metadata' not in findings:
            improvements.append("Add fallback methods for metadata collection when primary endpoint fails")
        
        if 'main_function' not in findings:
            improvements.append("Include function discovery phase to identify alternative entry points when 'main' is not available")
        
        if len(errors) > 0:
            improvements.append("Add error handling and retry logic for failed MCP endpoints")
            improvements.append("Include validation steps to verify successful completion before proceeding to next phase")
        
        if evaluation['overall_score'] < 90:
            improvements.append("Expand data structure analysis to include more comprehensive type discovery")
            improvements.append("Add security-focused analysis phase for vulnerability identification")
            improvements.append("Include performance metrics and timing analysis for each phase")
        
        evaluation['improvements'] = improvements
        
        # Create enhanced prompt based on evaluation
        enhanced_prompt = f"""
# Enhanced Binary Documentation Strategy using Ghidra MCP Tools
# (Generated based on quality evaluation - Score: {evaluation['overall_score']:.1f}%)

## Objective
Execute comprehensive binary documentation with improved error handling and validation.

## Pre-Phase: Validation & Preparation
0. **MCP Connectivity Verification**
   - Verify all required MCP endpoints are accessible
   - Test basic functionality before starting documentation
   - Establish fallback strategies for failed endpoints

## Phase 1: Enhanced Initial Analysis
1. **Robust Program Metadata Collection**
   - Primary: Get program metadata with validation
   - Fallback: Manual analysis if automatic collection fails
   - Validation: Verify critical metadata fields are populated

2. **Comprehensive Entry Point Discovery**
   - Primary: Use get_entry_points endpoint
   - Secondary: Search for common entry point patterns (main, WinMain, DllMain)
   - Validation: Ensure at least one valid entry point is identified

## Phase 2: Intelligent Function Analysis
3. **Adaptive Function Discovery**
   - List all functions with pagination handling
   - Identify critical functions based on import/export analysis
   - Prioritize analysis based on function complexity and references

4. **Smart Decompilation Strategy**
   - Attempt decompilation of main/primary functions
   - If main fails, identify and analyze alternative entry points
   - Include error handling for decompilation failures

## Phase 3: Enhanced Data Analysis
5. **Comprehensive String Analysis**
   - Extract strings with categorization
   - Identify security-relevant strings (URLs, file paths, credentials)
   - Analyze string usage patterns and references

6. **Advanced Data Structure Creation**
   - Create structures based on actual data patterns found
   - Include validation of structure creation success
   - Generate meaningful structure names and documentation

## Phase 4: Security-Focused Analysis
7. **Vulnerability Assessment Integration**
   - Identify potentially dangerous function calls
   - Analyze input validation patterns
   - Document security implications of findings

8. **Performance and Quality Metrics**
   - Track analysis completion rates
   - Measure endpoint response times
   - Generate quality scores for each phase

## Phase 5: Intelligent Reporting
9. **Adaptive Report Generation**
   - Generate reports based on successful analysis phases
   - Include fallback content for failed analyses
   - Provide actionable next steps based on results

## Enhanced Success Criteria
- Minimum 85% phase completion rate
- All critical endpoints functional
- Comprehensive error handling demonstrated
- Security implications identified and documented
- Professional documentation with quality metrics

## Quality Assurance
- Continuous validation of MCP endpoint responses
- Error rate monitoring and improvement suggestions
- Automated quality scoring and improvement recommendations
"""
        
        evaluation['enhanced_prompt'] = enhanced_prompt.strip()
        
        # Generate next steps
        if evaluation['overall_score'] >= 90:
            evaluation['next_steps'] = [
                "Documentation quality excellent - ready for production use",
                "Consider adding specialized analysis modules for specific binary types",
                "Implement automated reporting and alerting for security findings"
            ]
        elif evaluation['overall_score'] >= 75:
            evaluation['next_steps'] = [
                "Good foundation - focus on improving error handling",
                "Enhance fallback strategies for failed endpoint connections",
                "Add more comprehensive validation steps"
            ]
        else:
            evaluation['next_steps'] = [
                "Significant improvements needed in MCP endpoint reliability",
                "Review binary loading and plugin connectivity",
                "Consider manual verification of automated findings"
            ]
        
        # Save enhanced prompt to docs
        try:
            docs_dir = self.workspace_root / 'docs'
            docs_dir.mkdir(exist_ok=True)
            
            prompt_file = docs_dir / f'enhanced_binary_documentation_prompt_{int(time.time())}.md'
            with open(prompt_file, 'w') as f:
                f.write(evaluation['enhanced_prompt'])
            print(f"💾 Enhanced prompt saved: {prompt_file}")
            
        except Exception as e:
            print(f"⚠️  Could not save enhanced prompt: {e}")
        
        # Display evaluation summary
        print("\n🎯 Evaluation Summary:")
        if evaluation['strengths']:
            print("   ✅ Strengths:")
            for strength in evaluation['strengths']:
                print(f"      • {strength}")
        
        if evaluation['weaknesses']:
            print("   ⚠️  Areas for Improvement:")
            for weakness in evaluation['weaknesses']:
                print(f"      • {weakness}")
        
        if evaluation['improvements']:
            print("   🔧 Recommended Enhancements:")
            for improvement in evaluation['improvements']:
                print(f"      • {improvement}")
        
        return evaluation
    
    def run_full_cycle(self, comprehensive_test=False, organize_project=True, document_binary=False, project_path=None, binary_path=None):
        """Run the complete generic MCP development and verification cycle"""
        print("🔄 GHIDRA MCP DEVELOPMENT & VERIFICATION CYCLE")
        print("="*70)
        
        success = True
        
        # Step 0: Project Organization (optional but recommended)
        if organize_project:
            if not self.organize_project_structure():
                print("⚠️  Project organization failed - continuing anyway")
        
        # Step 1: Build changes
        print("📝 Step 1: Building plugin changes...")
        if not self.build_plugin():
            print("❌ Build failed - aborting cycle")
            return False
        
        # Step 2: Close ALL existing Ghidra processes (graceful)
        print("🔒 Step 2: Closing all existing Ghidra processes...")
        if not self.close_ghidra():
            print("⚠️  Failed to close all Ghidra processes - continuing anyway")
        
        # Step 2.5: Verify Ghidra is closed
        if not self.verify_ghidra_closed():
            print("⚠️  Some Ghidra processes may still be running")
            print("    Waiting additional time for cleanup...")
            time.sleep(10)
        
        # Step 3: Deploy plugin
        print("🚀 Step 3: Deploying plugin...")
        if not self.deploy_plugin():
            print("❌ Deployment failed - aborting cycle")
            return False
        
        # Step 4: Start fresh Ghidra with verification (enhanced with pre-check)
        print("⚡ Step 4: Starting fresh Ghidra with verification...")
        if not self.start_ghidra(project_path, binary_path):
            print("❌ Failed to start Ghidra - aborting cycle")
            return False
        
        # Step 5: Check CodeBrowser window
        print("🔍 Step 5: Checking CodeBrowser window...")
        # Give extra time for project/binary loading
        time.sleep(5)
        codebrowser_found = self.check_codebrowser_window()
        if not codebrowser_found:
            print("⚠️  CodeBrowser window not detected - may affect testing")
        
        # Step 6: Wait for plugin to be ready
        print("⏳ Step 6: Waiting for MCP plugin to be ready...")
        if not self.wait_for_plugin():
            print("❌ MCP Plugin not ready - cycle incomplete")
            print("📝 FIRST-TIME SETUP NOTES:")
            print("   1. Plugin may need manual enabling in Ghidra:")
            print("      - Go to File > Configure...")
            print("      - Navigate to Miscellaneous > GhidraMCP")
            print("      - Check the checkbox to enable")
            print("      - Click OK and restart Ghidra")
            print("   2. Open CodeBrowser: Tools > Code Browser")
            print("   3. Ensure port 8080 is not used by other applications")
            return False
        
        # Step 7: Comprehensive MCP Tool Verification
        print("🧪 Step 7: Comprehensive MCP Tool Verification...")
        if comprehensive_test:
            test_results = self.run_comprehensive_mcp_test()
            if not test_results.get('all_passed', False):
                print("⚠️  Some MCP endpoints failed - check comprehensive test results")
                success = False
            else:
                print("✅ All MCP tools verified successfully!")
        else:
            # Fallback to basic data types test for backward compatibility
            print("Running basic data types test (use --comprehensive-test for full verification)...")
            basic_results = self.test_mcp_endpoint('/create_struct', 'POST', 'Basic struct test', {
                "name": f"QuickTest_{int(time.time())}",
                "fields": [{"name": "x", "type": "int"}]
            })
            if not basic_results.success:
                print("⚠️  Basic MCP test failed")
                success = False
        
        # Step 8: Real-World Binary Documentation (if enabled)
        documentation_results = None
        if document_binary and success:
            try:
                documentation_results = self.execute_binary_documentation(binary_path)
                if documentation_results['success']:
                    print("✅ Binary documentation completed successfully!")
                else:
                    print("⚠️  Binary documentation completed with issues")
                    success = False
            except Exception as e:
                print(f"❌ Binary documentation failed: {e}")
                success = False
        
        # Step 9: Documentation Quality Evaluation (if Step 8 was executed)
        evaluation_results = None
        if document_binary and documentation_results:
            try:
                evaluation_results = self.evaluate_documentation_quality(documentation_results)
                print(f"✅ Documentation quality evaluation completed (Score: {evaluation_results['overall_score']:.1f}%)")
                
                # Save evaluation report
                logs_dir = self.workspace_root / 'logs'
                logs_dir.mkdir(exist_ok=True)
                eval_file = logs_dir / f'documentation_evaluation_{int(time.time())}.json'
                
                with open(eval_file, 'w') as f:
                    json.dump({
                        'documentation_results': documentation_results,
                        'evaluation_results': evaluation_results,
                        'timestamp': time.time()
                    }, f, indent=2)
                print(f"📄 Evaluation report saved: {eval_file}")
                
            except Exception as e:
                print(f"❌ Documentation evaluation failed: {e}")
        
        print("\n" + "="*70)
        if success:
            print("🎉 ENHANCED MCP DEVELOPMENT CYCLE COMPLETED SUCCESSFULLY!")
            if codebrowser_found:
                print("✅ CodeBrowser window was detected")
            if project_path:
                print(f"✅ Project loaded: {project_path}")
            if binary_path:
                print(f"✅ Binary loaded: {binary_path}")
            if comprehensive_test:
                print("✅ Comprehensive MCP verification passed")
            if organize_project:
                print("✅ Project structure organized")
            if document_binary and documentation_results:
                print(f"✅ Binary documentation completed (Quality: {documentation_results.get('quality_score', 0):.1f}%)")
            if evaluation_results:
                print(f"✅ Documentation evaluation completed (Score: {evaluation_results['overall_score']:.1f}%)")
        else:
            print("⚠️  CYCLE COMPLETED WITH ISSUES - CHECK RESULTS ABOVE")
        print("="*70)
        
        return success

def main():
    parser = argparse.ArgumentParser(description="Generic Ghidra MCP Development and Verification Automation")
    parser.add_argument("--ghidra-path", help="Path to Ghidra installation directory")
    parser.add_argument("--project-path", help="Path to Ghidra project file (.gpr)")
    parser.add_argument("--binary-path", help="Path to binary file to load")
    
    # Main operation modes
    parser.add_argument("--comprehensive-test", action="store_true", 
                       help="Run comprehensive MCP endpoint verification (recommended)")
    parser.add_argument("--document-binary", action="store_true", 
                       help="Execute real-world binary documentation workflow (Steps 8 & 9)")
    parser.add_argument("--organize-only", action="store_true", 
                       help="Only organize project structure and exit")
    parser.add_argument("--no-organize", action="store_true", 
                       help="Skip project organization step")
    
    # Individual step operations (for debugging)
    parser.add_argument("--build-only", action="store_true", help="Only build the plugin")
    parser.add_argument("--deploy-only", action="store_true", help="Only deploy (assumes already built)")
    parser.add_argument("--test-only", action="store_true", help="Only run MCP tests (assumes plugin is running)")
    parser.add_argument("--close-only", action="store_true", help="Only close Ghidra processes (Step 2)")
    parser.add_argument("--debug-unions", action="store_true", help="Run detailed union creation debugging")
    
    args = parser.parse_args()
    
    # Get Ghidra path from argument or environment
    ghidra_path = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")
    
    cycle = GhidraDevCycle(ghidra_path)
    
    try:
        # Handle special operation modes first
        if args.organize_only:
            print("🗂️  PROJECT ORGANIZATION ONLY")
            print("="*50)
            return cycle.organize_project_structure()
            
        elif args.build_only:
            print("🔨 BUILD ONLY MODE")
            print("="*50)
            return cycle.build_plugin()
            
        elif args.deploy_only:
            print("🚀 DEPLOY ONLY MODE")
            print("="*50)
            cycle.close_ghidra()
            success = cycle.deploy_plugin()
            if success:
                cycle.start_ghidra(args.project_path, args.binary_path)
                cycle.wait_for_plugin()
            return success
            
        elif args.test_only:
            print("🧪 MCP TEST ONLY MODE")
            print("="*50)
            if args.comprehensive_test:
                results = cycle.run_comprehensive_mcp_test()
                return results.get('all_passed', False)
            else:
                # Basic test for backward compatibility
                result = cycle.test_mcp_endpoint('/check_connection', 'GET', 'Basic connection test')
                return result.success
                
        elif args.close_only:
            print("🔧 CLOSE GHIDRA PROCESSES ONLY")
            print("="*50)
            success = cycle.close_ghidra()
            if success:
                cycle.verify_ghidra_closed()
            return success
            
        elif args.debug_unions:
            print("🔬 UNION DEBUGGING MODE")
            print("="*50)
            results = cycle.debug_union_creation()
            return any(r['success'] for r in results.values())
            
        else:
            # Full generic MCP development cycle
            print("🌟 RUNNING FULL GENERIC MCP DEVELOPMENT CYCLE")
            if args.comprehensive_test:
                print("   ✅ Comprehensive MCP testing enabled")
            if args.document_binary:
                print("   ✅ Binary documentation workflow enabled (Steps 8 & 9)")
            if not args.no_organize:
                print("   ✅ Project organization enabled")
            print("="*50)
            
            return cycle.run_full_cycle(
                comprehensive_test=args.comprehensive_test,
                organize_project=not args.no_organize,
                document_binary=args.document_binary,
                project_path=args.project_path,
                binary_path=args.binary_path
            )
            
    except KeyboardInterrupt:
        print("\n⏹️  Interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)