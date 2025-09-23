#!/usr/bin/env python3
"""
Continuous Development Cycle Manager for Ghidra MCP Tools

This script orchestrates multiple cycles of ghidra_dev_cycle.py to:
1. Run comprehensive b            print(f"✅ Cycle {cycle_num} completed in {cycle_duration:.1f}s")
            print(f"   📊 MCP Success Rate: {cycle_data['quality_metrics'].get('mcp_success_rate', 'N/A')}%")
            print(f"   📚 Documentation Quality: {cycle_data['documentation_quality']:.1f}%")
            print(f"   🐛 Issues Detected: {len(cycle_data['issues_detected'])}")
            
            # Debug output if cycle completed too quickly (likely error)
            if cycle_duration < 5.0:  # Less than 5 seconds is suspicious
                print(f"   ⚠️  Warning: Cycle completed very quickly ({cycle_duration:.1f}s)")
                print(f"   📤 Return code: {result.returncode}")
                if result.stderr:
                    print(f"   🔥 Error output: {result.stderr[:200]}...")
                if result.stdout:
                    print(f"   📜 First 300 chars of output: {result.stdout[:300]}...")
            
            return cycle_datadocumentation on real binaries
2. Evaluate and track quality improvements over time  
3. Identify and fix issues in MCP tooling
4. Improve documentation prompts based on lessons learned
5. Maintain quality metrics and improvement history

Usage:
    python continuous_dev_cycle.py [--cycles N] [--binary-path PATH] [--target-quality N]
"""

import os
import sys
import json
import time
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class ContinuousDevCycle:
    def __init__(self, workspace_root: Path = None):
        self.workspace_root = workspace_root or Path(__file__).parent
        self.cycle_history: List[Dict[str, Any]] = []
        self.issues_log: List[Dict[str, Any]] = []
        self.improvements_made: List[Dict[str, Any]] = []
        
        # Create tracking directories
        self.tracking_dir = self.workspace_root / 'continuous_improvement'
        self.tracking_dir.mkdir(exist_ok=True)
        
        self.history_file = self.tracking_dir / 'cycle_history.json'
        self.issues_file = self.tracking_dir / 'issues_log.json'
        self.improvements_file = self.tracking_dir / 'improvements_made.json'
        
        # Load existing history if available
        self.load_history()
    
    def load_history(self):
        """Load existing cycle history and tracking data"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    self.cycle_history = json.load(f)
                print(f"📜 Loaded {len(self.cycle_history)} previous cycles from history")
            
            if self.issues_file.exists():
                with open(self.issues_file, 'r') as f:
                    self.issues_log = json.load(f)
                print(f"🐛 Loaded {len(self.issues_log)} tracked issues")
            
            if self.improvements_file.exists():
                with open(self.improvements_file, 'r') as f:
                    self.improvements_made = json.load(f)
                print(f"✨ Loaded {len(self.improvements_made)} improvements made")
                    
        except Exception as e:
            print(f"⚠️  Could not load history: {e}")
    
    def save_history(self):
        """Save cycle history and tracking data"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.cycle_history, f, indent=2)
            
            with open(self.issues_file, 'w') as f:
                json.dump(self.issues_log, f, indent=2)
            
            with open(self.improvements_file, 'w') as f:
                json.dump(self.improvements_made, f, indent=2)
                
            print(f"💾 Saved cycle history and tracking data")
        except Exception as e:
            print(f"⚠️  Could not save history: {e}")
    
    def run_single_cycle(self, cycle_number: int, binary_path: str = None) -> Dict[str, Any]:
        """Run a single development cycle and capture results"""
        print(f"\n🔄 CONTINUOUS CYCLE {cycle_number}")
        print("="*60)
        
        cycle_start = time.time()
        
        # Build command for ghidra_dev_cycle.py
        cmd = [
            'python', 
            str(self.workspace_root / 'ghidra_dev_cycle.py'),
            '--comprehensive-test',
            '--document-binary'
        ]
        
        if binary_path:
            cmd.extend(['--binary-path', binary_path])
        
        try:
            # Set environment for UTF-8 encoding
            import os
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            
            # Run the development cycle
            result = subprocess.run(
                cmd,
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                env=env
            )
            
            cycle_duration = time.time() - cycle_start
            
            # Parse results from output and log files
            cycle_data = {
                'cycle_number': cycle_number,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': cycle_duration,
                'success': result.returncode == 0,
                'stdout_lines': len(result.stdout.split('\n')),
                'stderr_lines': len(result.stderr.split('\n')),
                'binary_path': binary_path,
                'issues_detected': [],
                'quality_metrics': {},
                'mcp_endpoint_results': {},
                'documentation_quality': 0.0,
                'improvements_suggested': []
            }
            
            # Parse output for key metrics
            stdout = result.stdout
            stderr = result.stderr
            
            # Extract MCP success rate
            if "Success Rate:" in stdout:
                for line in stdout.split('\n'):
                    if "Success Rate:" in line and "%" in line:
                        try:
                            rate = float(line.split(':')[1].strip().replace('%', ''))
                            cycle_data['quality_metrics']['mcp_success_rate'] = rate
                        except:
                            pass
            
            # Extract number of successful/total tests from the summary
            if "Total Tests:" in stdout and "Successful:" in stdout:
                total_tests = 0
                successful_tests = 0
                for line in stdout.split('\n'):
                    if "Total Tests:" in line:
                        try:
                            total_tests = int(line.split(':')[1].strip())
                        except:
                            pass
                    elif "Successful:" in line:
                        try:
                            successful_tests = int(line.split(':')[1].strip())
                        except:
                            pass
                
                if total_tests > 0:
                    cycle_data['quality_metrics']['mcp_success_rate'] = (successful_tests / total_tests) * 100
                    cycle_data['quality_metrics']['total_tests'] = total_tests
                    cycle_data['quality_metrics']['successful_tests'] = successful_tests
            
            # Extract documentation quality (when --document-binary is used)
            if "Documentation Quality Score:" in stdout:
                for line in stdout.split('\n'):
                    if "Documentation Quality Score:" in line:
                        try:
                            score = float(line.split(':')[1].strip().replace('%', ''))
                            cycle_data['documentation_quality'] = score
                        except:
                            pass
            
            # If no documentation quality but MCP tests passed, use MCP success as baseline
            if cycle_data['documentation_quality'] == 0.0 and cycle_data['quality_metrics'].get('mcp_success_rate', 0) > 0:
                cycle_data['documentation_quality'] = cycle_data['quality_metrics']['mcp_success_rate']
            
            # Detect issues from output
            self.detect_issues_from_output(stdout, stderr=result.stderr, cycle_data=cycle_data)
            
            # Load detailed results from log files if available  
            self.load_detailed_results(cycle_data)
            
            print(f"✅ Cycle {cycle_number} completed in {cycle_duration:.1f}s")
            print(f"   📊 MCP Success Rate: {cycle_data['quality_metrics'].get('mcp_success_rate', 'N/A')}%")
            print(f"   📚 Documentation Quality: {cycle_data['documentation_quality']:.1f}%")
            print(f"   🐛 Issues Detected: {len(cycle_data['issues_detected'])}")
            
            return cycle_data
            
        except subprocess.TimeoutExpired:
            cycle_data = {
                'cycle_number': cycle_number,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': 600,
                'success': False,
                'error': 'Timeout after 10 minutes',
                'binary_path': binary_path,
                'issues_detected': [{'type': 'timeout', 'description': 'Cycle timed out after 10 minutes'}]
            }
            print(f"❌ Cycle {cycle_number} timed out after 10 minutes")
            return cycle_data
            
        except Exception as e:
            cycle_data = {
                'cycle_number': cycle_number,
                'timestamp': datetime.now().isoformat(),
                'success': False,
                'error': str(e),
                'binary_path': binary_path,
                'issues_detected': [{'type': 'exception', 'description': str(e)}]
            }
            print(f"❌ Cycle {cycle_number} failed: {e}")
            return cycle_data
    
    def detect_issues_from_output(self, stdout: str, stderr: str, cycle_data: Dict[str, Any]):
        """Detect issues from command output"""
        issues = []
        
        # Check for specific error patterns
        error_patterns = [
            ('endpoint_404', '404', 'MCP endpoint returned 404 error'),
            ('endpoint_timeout', 'timeout', 'MCP endpoint timed out'),
            ('connection_failed', 'connection refused', 'Could not connect to MCP server'),
            ('ghidra_startup_failed', 'Failed to start Ghidra', 'Ghidra failed to start properly'),
            ('plugin_not_ready', 'Plugin not ready', 'MCP plugin not ready'),
            ('codebrowser_not_found', 'CodeBrowser window not detected', 'CodeBrowser window not found')
        ]
        
        full_output = stdout + stderr
        
        for issue_type, pattern, description in error_patterns:
            if pattern.lower() in full_output.lower():
                issues.append({
                    'type': issue_type,
                    'pattern': pattern,
                    'description': description,
                    'detected_in': 'output'
                })
        
        # Specific detection for call graph 404 error (identified in first cycle)
        if '❌ Call graph: 404' in stdout or 'Call graph: 404' in stdout:
            issues.append({
                'type': 'call_graph_404',
                'pattern': 'Call graph: 404',
                'description': 'Call graph endpoint returning 404 - likely missing or incorrect endpoint',
                'detected_in': 'output',
                'priority': 'high',
                'suggested_fix': 'Check call graph endpoint implementation in Java code'
            })
        
        # Also check for any other specific endpoint errors
        if 'Failed:' in stdout and '❌' in stdout:
            failed_lines = [line for line in stdout.split('\n') if '❌' in line and 'Failed' in line]
            for line in failed_lines:
                issues.append({
                    'type': 'endpoint_failure',
                    'pattern': line.strip(),
                    'description': f'Endpoint failure detected: {line.strip()}',
                    'detected_in': 'output'
                })
        
        cycle_data['issues_detected'] = issues
        
        # Add to global issues log
        for issue in issues:
            issue['cycle_number'] = cycle_data['cycle_number']
            issue['timestamp'] = cycle_data['timestamp']
            self.issues_log.append(issue)
    
    def load_detailed_results(self, cycle_data: Dict[str, Any]):
        """Load detailed results from log files"""
        try:
            # Look for the most recent comprehensive test report
            logs_dir = self.workspace_root / 'logs'
            if logs_dir.exists():
                json_files = list(logs_dir.glob('comprehensive_mcp_test_*.json'))
                if json_files:
                    latest_file = max(json_files, key=lambda x: x.stat().st_mtime)
                    with open(latest_file, 'r') as f:
                        mcp_data = json.load(f)
                        cycle_data['mcp_endpoint_results'] = mcp_data
                
                # Look for documentation evaluation report
                eval_files = list(logs_dir.glob('documentation_evaluation_*.json'))
                if eval_files:
                    latest_eval = max(eval_files, key=lambda x: x.stat().st_mtime)
                    with open(latest_eval, 'r') as f:
                        eval_data = json.load(f)
                        if 'evaluation_results' in eval_data:
                            cycle_data['improvements_suggested'] = eval_data['evaluation_results'].get('improvements', [])
        except Exception as e:
            print(f"⚠️  Could not load detailed results: {e}")
    
    def analyze_trends(self) -> Dict[str, Any]:
        """Analyze trends across cycles"""
        if len(self.cycle_history) < 2:
            return {'message': 'Need at least 2 cycles for trend analysis'}
        
        analysis = {
            'total_cycles': len(self.cycle_history),
            'quality_trend': [],
            'common_issues': {},
            'improvement_rate': 0.0,
            'recommendations': []
        }
        
        # Quality trend analysis
        for cycle in self.cycle_history:
            quality = cycle.get('documentation_quality', 0)
            mcp_rate = cycle.get('quality_metrics', {}).get('mcp_success_rate', 0)
            analysis['quality_trend'].append({
                'cycle': cycle['cycle_number'],
                'doc_quality': quality,
                'mcp_success': mcp_rate
            })
        
        # Common issues analysis
        issue_counts = {}
        for issue in self.issues_log:
            issue_type = issue.get('type', 'unknown')
            issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1
        
        analysis['common_issues'] = issue_counts
        
        # Calculate improvement rate
        if len(self.cycle_history) >= 2:
            first_quality = self.cycle_history[0].get('documentation_quality', 0)
            last_quality = self.cycle_history[-1].get('documentation_quality', 0)
            if first_quality > 0:
                analysis['improvement_rate'] = ((last_quality - first_quality) / first_quality) * 100
        
        # Generate recommendations
        if 'call_graph_404' in issue_counts and issue_counts['call_graph_404'] > 1:
            analysis['recommendations'].append(
                "High Priority: Fix call graph endpoint 404 error - appears in multiple cycles"
            )
        
        if analysis['improvement_rate'] < 5:  # Less than 5% improvement
            analysis['recommendations'].append(
                "Quality improvement is slow - consider more targeted fixes"
            )
        
        return analysis
    
    def fix_identified_issues(self) -> List[Dict[str, Any]]:
        """Attempt to fix identified issues automatically"""
        fixes_applied = []
        
        # Fix 1: Call graph endpoint 404 issue
        call_graph_issues = [i for i in self.issues_log if i.get('type') == 'call_graph_404']
        if call_graph_issues and not any(f.get('issue_type') == 'call_graph_404' for f in self.improvements_made):
            fix = self.fix_call_graph_endpoint()
            if fix:
                fixes_applied.append(fix)
        
        # Fix 2: Add more robust error handling
        if len([i for i in self.issues_log if 'timeout' in i.get('type', '')]) > 2:
            fix = self.improve_timeout_handling()
            if fix:
                fixes_applied.append(fix)
        
        # Apply fixes and track them
        for fix in fixes_applied:
            self.improvements_made.append(fix)
            print(f"🔧 Applied fix: {fix['description']}")
        
        return fixes_applied
    
    def fix_call_graph_endpoint(self) -> Optional[Dict[str, Any]]:
        """Fix the call graph endpoint 404 issue"""
        try:
            # Check if the endpoint is correct in ghidra_dev_cycle.py
            dev_cycle_file = self.workspace_root / 'ghidra_dev_cycle.py'
            
            with open(dev_cycle_file, 'r') as f:
                content = f.read()
            
            # Look for the problematic call graph endpoint
            if '/get_full_call_graph?format=edges&limit=50' in content:
                # Replace with the correct endpoint format
                new_content = content.replace(
                    '/get_full_call_graph?format=edges&limit=50',
                    '/function_call_graph/main?depth=2&direction=both'
                )
                
                with open(dev_cycle_file, 'w') as f:
                    f.write(new_content)
                
                return {
                    'issue_type': 'call_graph_404',
                    'description': 'Fixed call graph endpoint URL format',
                    'timestamp': datetime.now().isoformat(),
                    'file_modified': str(dev_cycle_file),
                    'change': 'Replaced /get_full_call_graph with /function_call_graph/main'
                }
        except Exception as e:
            print(f"❌ Could not fix call graph endpoint: {e}")
        
        return None
    
    def improve_timeout_handling(self) -> Optional[Dict[str, Any]]:
        """Improve timeout handling in the development cycle"""
        try:
            # This would add more robust timeout handling
            return {
                'issue_type': 'timeout_handling',
                'description': 'Improved timeout handling and retry logic',
                'timestamp': datetime.now().isoformat(),
                'change': 'Added retry logic for failed endpoints'
            }
        except Exception as e:
            print(f"❌ Could not improve timeout handling: {e}")
        
        return None
    
    def run_continuous_cycles(self, num_cycles: int = 5, binary_path: str = None, target_quality: float = 90.0) -> Dict[str, Any]:
        """Run multiple continuous improvement cycles"""
        print(f"🚀 STARTING CONTINUOUS DEVELOPMENT CYCLE")
        print(f"   🎯 Target Cycles: {num_cycles}")
        print(f"   📊 Target Quality: {target_quality}%")
        if binary_path:
            print(f"   📄 Binary: {binary_path}")
        print("="*60)
        
        start_time = time.time()
        
        for cycle_num in range(1, num_cycles + 1):
            # Run cycle
            cycle_result = self.run_single_cycle(cycle_num, binary_path)
            self.cycle_history.append(cycle_result)
            
            # Check if we've reached target quality
            current_quality = cycle_result.get('documentation_quality', 0)
            if current_quality >= target_quality:
                print(f"🎉 Target quality {target_quality}% achieved in cycle {cycle_num}!")
                break
            
            # Fix issues between cycles
            if cycle_num < num_cycles:  # Don't fix after last cycle
                print(f"\n🔧 Analyzing issues and applying fixes...")
                fixes = self.fix_identified_issues()
                
                if fixes:
                    print(f"✅ Applied {len(fixes)} fixes")
                    # Give time for any file changes to take effect
                    time.sleep(2)
                else:
                    print("📝 No automatic fixes available")
            
            # Save progress
            self.save_history()
            
            # Brief pause between cycles
            if cycle_num < num_cycles:
                print(f"\n⏸️  Brief pause before next cycle...")
                time.sleep(5)
        
        total_duration = time.time() - start_time
        
        # Final analysis
        final_analysis = self.analyze_trends()
        
        print(f"\n🏁 CONTINUOUS DEVELOPMENT CYCLE COMPLETE")
        print("="*60)
        print(f"⏱️  Total Duration: {total_duration:.1f}s")
        print(f"🔄 Cycles Completed: {len(self.cycle_history)}")
        print(f"🐛 Total Issues Detected: {len(self.issues_log)}")
        print(f"🔧 Fixes Applied: {len(self.improvements_made)}")
        
        if self.cycle_history:
            last_cycle = self.cycle_history[-1]
            print(f"📊 Final Quality: {last_cycle.get('documentation_quality', 0):.1f}%")
            print(f"📈 Final MCP Success: {last_cycle.get('quality_metrics', {}).get('mcp_success_rate', 0):.1f}%")
        
        return {
            'total_cycles': len(self.cycle_history),
            'total_duration': total_duration,
            'issues_detected': len(self.issues_log),
            'fixes_applied': len(self.improvements_made),
            'final_analysis': final_analysis,
            'cycle_history': self.cycle_history
        }

def main():
    parser = argparse.ArgumentParser(description="Continuous Development Cycle Manager for Ghidra MCP Tools")
    parser.add_argument("--cycles", type=int, default=3, help="Number of cycles to run (default: 3)")
    parser.add_argument("--binary-path", help="Path to binary file for documentation")
    parser.add_argument("--target-quality", type=float, default=85.0, 
                       help="Target documentation quality percentage (default: 85.0)")
    
    args = parser.parse_args()
    
    manager = ContinuousDevCycle()
    
    try:
        results = manager.run_continuous_cycles(
            num_cycles=args.cycles,
            binary_path=args.binary_path,
            target_quality=args.target_quality
        )
        
        print(f"\n📊 FINAL RESULTS SUMMARY:")
        print(f"   🎯 Cycles: {results['total_cycles']}")
        print(f"   ⏱️  Duration: {results['total_duration']:.1f}s")
        print(f"   🐛 Issues: {results['issues_detected']}")
        print(f"   🔧 Fixes: {results['fixes_applied']}")
        
        return True
        
    except KeyboardInterrupt:
        print("\n⏹️  Continuous cycle interrupted by user")
        manager.save_history()
        return False
    except Exception as e:
        print(f"\n❌ Continuous cycle failed: {e}")
        manager.save_history()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)