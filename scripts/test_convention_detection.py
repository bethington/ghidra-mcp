#!/usr/bin/env python3
"""
Test Strategy for DetectD2CallingConventions.py

This script validates the detection accuracy by:
1. Running detection on known ground truth functions
2. Comparing detected conventions against expected conventions
3. Generating accuracy metrics and confusion matrix
4. Identifying false positives and false negatives
"""

import json
import sys
from pathlib import Path

# Add parent directory to path for bridge import
sys.path.insert(0, str(Path(__file__).parent.parent))

from bridge_mcp_ghidra import (
    run_ghidra_script,
    decompile_function,
    get_function_xrefs,
    disassemble_function,
    list_functions
)

# Ground Truth Dataset - Functions with known calling conventions
GROUND_TRUTH = {
    '__d2call': [
        # Add known __d2call functions from your analysis
        {'address': '0x6fd5e490', 'name': 'CalculateSkillAnimationId'},
        # Add more verified __d2call functions
    ],
    '__d2regcall': [
        # Add known __d2regcall functions
        {'address': '0x6fd94ba0', 'name': 'CreateOppositeDirectionNodes'},
        # Add more verified __d2regcall functions
    ],
    '__d2mixcall': [
        # Add known __d2mixcall functions
        {'address': '0x6fd94950', 'name': 'FindOrCreateNodeInList'},
        # Add more verified __d2mixcall functions
    ],
    '__d2edicall': [
        # Add known __d2edicall functions (EDI context pointer)
        # {'address': '0x????????', 'name': 'ProcessRoomLevel'},
    ],
    '__stdcall': [
        # Add some standard convention functions for comparison
    ],
    '__cdecl': [
        # Add some cdecl functions
    ]
}


class ConventionDetectionTester:
    def __init__(self):
        self.results = {
            'true_positives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'true_negatives': 0,
            'by_convention': {},
            'confusion_matrix': {},
            'misclassified': []
        }
        
    def run_detection_script(self):
        """Run the DetectD2CallingConventions.py script via Ghidra MCP"""
        print("[*] Running detection script in Ghidra...")
        
        script_path = Path(__file__).parent.parent / "ghidra_scripts" / "DetectD2CallingConventions.py"
        
        try:
            result = run_ghidra_script(str(script_path))
            print("[✓] Detection script completed")
            return self.parse_detection_output(result)
        except Exception as e:
            print(f"[✗] Error running detection script: {e}")
            return None
    
    def parse_detection_output(self, output):
        """Parse the detection script output to extract detected functions"""
        detected = {
            '__d2call': [],
            '__d2regcall': [],
            '__d2mixcall': [],
            '__d2edicall': []
        }
        
        # TODO: Parse the console output or CSV export
        # For now, you'd need to modify DetectD2CallingConventions.py to export JSON
        
        return detected
    
    def validate_against_ground_truth(self, detected):
        """Compare detected conventions against ground truth"""
        print("\n[*] Validating against ground truth...")
        
        for expected_conv, functions in GROUND_TRUTH.items():
            if expected_conv not in ['__d2call', '__d2regcall', '__d2mixcall', '__d2edicall']:
                continue  # Skip standard conventions for now
                
            for func in functions:
                func_addr = func['address']
                func_name = func['name']
                
                # Check if function was detected with correct convention
                detected_conv = self.find_detected_convention(func_addr, detected)
                
                if detected_conv == expected_conv:
                    self.results['true_positives'] += 1
                    print(f"  [✓] {func_name} @ {func_addr}: Correctly detected as {expected_conv}")
                elif detected_conv is None:
                    self.results['false_negatives'] += 1
                    print(f"  [✗] {func_name} @ {func_addr}: NOT DETECTED (expected {expected_conv})")
                    self.results['misclassified'].append({
                        'address': func_addr,
                        'name': func_name,
                        'expected': expected_conv,
                        'detected': 'None',
                        'type': 'false_negative'
                    })
                else:
                    self.results['false_positives'] += 1
                    print(f"  [✗] {func_name} @ {func_addr}: Detected as {detected_conv} (expected {expected_conv})")
                    self.results['misclassified'].append({
                        'address': func_addr,
                        'name': func_name,
                        'expected': expected_conv,
                        'detected': detected_conv,
                        'type': 'misclassification'
                    })
    
    def find_detected_convention(self, address, detected):
        """Find which convention a function was detected as"""
        for conv, funcs in detected.items():
            for func in funcs:
                if func['address'] == address:
                    return conv
        return None
    
    def manual_validation(self, sample_size=10):
        """Manually validate a random sample of detections"""
        print(f"\n[*] Manual validation of {sample_size} random detections...")
        print("For each function, examine the disassembly and confirm:")
        print("  1. Register usage matches convention")
        print("  2. Stack parameter access is correct")
        print("  3. Return instruction type is correct")
        print()
        
        # TODO: Randomly sample detected functions and display their patterns
    
    def analyze_confidence_distribution(self, detected):
        """Analyze the distribution of confidence scores"""
        print("\n[*] Confidence Score Analysis:")
        
        for conv, funcs in detected.items():
            if not funcs:
                continue
                
            confidences = [f['confidence'] for f in funcs]
            avg_conf = sum(confidences) / len(confidences)
            min_conf = min(confidences)
            max_conf = max(confidences)
            
            print(f"\n  {conv}:")
            print(f"    Count: {len(funcs)}")
            print(f"    Avg Confidence: {avg_conf:.1%}")
            print(f"    Range: {min_conf:.1%} - {max_conf:.1%}")
            
            # Flag low confidence detections for review
            low_conf = [f for f in funcs if f['confidence'] < 0.8]
            if low_conf:
                print(f"    ⚠️  {len(low_conf)} detections below 80% confidence")
    
    def test_caller_pattern_detection(self):
        """Test that caller analysis is working"""
        print("\n[*] Testing caller pattern detection...")
        
        # Pick a known function and examine its callers
        test_func = {'address': '0x6fd5e490', 'name': 'CalculateSkillAnimationId'}
        
        print(f"  Analyzing callers of {test_func['name']}...")
        
        try:
            xrefs = get_function_xrefs(name=test_func['name'], limit=5)
            
            for xref in xrefs:
                caller_addr = xref.get('from_address')
                print(f"\n  Caller @ {caller_addr}:")
                
                # Get disassembly around the CALL instruction
                disasm = disassemble_function(address=caller_addr)
                
                # Look for MOV EBX pattern before CALL
                lines = disasm.split('\n')
                for i, line in enumerate(lines):
                    if 'CALL' in line and test_func['address'] in line:
                        # Show 5 instructions before CALL
                        context = lines[max(0, i-5):i+1]
                        print("    " + "\n    ".join(context))
                        
                        # Verify pattern
                        has_mov_ebx = any('MOV EBX' in l for l in context)
                        has_push = any('PUSH' in l for l in context)
                        
                        print(f"    Pattern: MOV EBX={has_mov_ebx}, PUSH={has_push}")
                        
        except Exception as e:
            print(f"  Error: {e}")
    
    def test_edge_cases(self):
        """Test edge cases and potential false positives"""
        print("\n[*] Testing edge cases...")
        
        test_cases = [
            {
                'name': 'Tiny thunk function',
                'description': 'Should be filtered out (<5 instructions)',
                # Test a known thunk
            },
            {
                'name': 'Wrapper function',
                'description': 'Function that just passes through to another',
                # Test a wrapper
            },
            {
                'name': 'Register save-heavy function',
                'description': 'Function with many PUSH instructions at start',
                # Test a function that saves many registers
            }
        ]
        
        # TODO: Implement specific edge case tests
    
    def generate_report(self):
        """Generate final test report"""
        print("\n" + "="*70)
        print("DETECTION VALIDATION REPORT")
        print("="*70)
        
        total = (self.results['true_positives'] + 
                self.results['false_positives'] + 
                self.results['false_negatives'])
        
        if total > 0:
            accuracy = self.results['true_positives'] / total
            precision = self.results['true_positives'] / (
                self.results['true_positives'] + self.results['false_positives']
            ) if (self.results['true_positives'] + self.results['false_positives']) > 0 else 0
            
            recall = self.results['true_positives'] / (
                self.results['true_positives'] + self.results['false_negatives']
            ) if (self.results['true_positives'] + self.results['false_negatives']) > 0 else 0
            
            print(f"\nOverall Accuracy: {accuracy:.1%}")
            print(f"Precision: {precision:.1%}")
            print(f"Recall: {recall:.1%}")
            
        print(f"\nTrue Positives:  {self.results['true_positives']}")
        print(f"False Positives: {self.results['false_positives']}")
        print(f"False Negatives: {self.results['false_negatives']}")
        
        if self.results['misclassified']:
            print("\nMisclassified Functions:")
            for miss in self.results['misclassified'][:10]:
                print(f"  {miss['name']} @ {miss['address']}")
                print(f"    Expected: {miss['expected']}, Detected: {miss['detected']}")


def main():
    """Main test execution"""
    print("="*70)
    print("DetectD2CallingConventions.py - TEST SUITE")
    print("="*70 + "\n")
    
    tester = ConventionDetectionTester()
    
    # Phase 1: Run detection
    detected = tester.run_detection_script()
    
    if detected:
        # Phase 2: Validate against ground truth
        tester.validate_against_ground_truth(detected)
        
        # Phase 3: Analyze confidence distribution
        tester.analyze_confidence_distribution(detected)
        
        # Phase 4: Test specific features
        tester.test_caller_pattern_detection()
        tester.test_edge_cases()
        
        # Phase 5: Generate report
        tester.generate_report()
    else:
        print("[✗] Could not run detection script")


if __name__ == '__main__':
    main()
