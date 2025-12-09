#Analyze Diablo II Animation and AI Loops
#
#This script detects and documents tight loops used for:
#1. Animation frame processing
#2. AI decision making
#3. Monster behavior updates
#4. Movement path calculation
#
#Diablo II uses several distinct loop patterns for performance-critical code.
#This script identifies them and suggests appropriate optimizations.
#
#Key patterns detected:
#- Frame update loops (dwGfxFrame, dwFrameRemain increment/decrement)
#- Direction iteration loops (8-direction or 16-direction)
#- Monster AI state machines
#- Skill execution loops
#- Item list iteration loops
#
#Output:
#- Console listing of detected loops
#- Loop characteristics and optimization hints
#- Confidence scores for each detection
#
#@author Ben Ethington
#@category Diablo 2
#@description Detects and documents animation frames, AI loops, and performance-critical code patterns
#@keybinding
#@menupath Diablo II.Analyze Loops and AI
#
"""
Supporting documentation for Loop and AI Analyzer
"""

import re

class LoopAnalyzer:
    def __init__(self):
        self.listing = currentProgram.getListing()
        self.func_mgr = currentProgram.getFunctionManager()
        self.monitor = monitor
        self.loops_found = []

    def log(self, msg):
        print("[LoopAnalyzer] " + msg)

    def analyze_function(self, func):
        """Analyze a single function for loops"""
        func_name = func.getName()
        entry = func.getEntryPoint()

        if entry is None:
            return

        # Scan function for loop patterns
        loops = self.detect_loops(func)

        if loops:
            for loop_info in loops:
                self.loops_found.append({
                    'function': func_name,
                    'address': entry.toString(),
                    'loop_type': loop_info['type'],
                    'loop_start': loop_info['start'].toString(),
                    'loop_end': loop_info['end'].toString(),
                    'characteristics': loop_info['characteristics'],
                    'confidence': loop_info['confidence']
                })

    def detect_loops(self, func):
        """Detect loops in a function"""
        loops = []
        visited = set()

        entry = func.getEntryPoint()
        if entry is None:
            return loops

        # Scan for backward branches (loop indicators)
        body = func.getBody()
        instr = self.listing.getInstructionAt(entry)
        branch_targets = {}

        while instr is not None and body.contains(instr.getAddress()):
            addr = instr.getAddress().getOffset()

            # Find all branches
            if instr.getMnemonicString().startswith('J'):
                # Conditional or unconditional jump
                refs = instr.getFlows()
                for flow_addr in refs:
                    target_offset = flow_addr.getOffset()

                    # Backward branch = loop
                    if target_offset < addr:
                        loop_type, characteristics = self.classify_loop(instr, target_offset)

                        if loop_type:
                            loops.append({
                                'type': loop_type,
                                'start': flow_addr,
                                'end': instr.getAddress(),
                                'characteristics': characteristics,
                                'confidence': 0.8
                            })

            instr = instr.getNext()

        return loops

    def classify_loop(self, branch_instr, loop_start):
        """Classify loop by its characteristics"""
        characteristics = []
        loop_type = "Generic"

        # Scan the loop for specific patterns
        current = branch_instr.getPrevious()
        scan_depth = 0

        while current is not None and scan_depth < 50:
            scan_depth += 1
            op_str = current.toString()

            # Animation frame update pattern
            if 'dwGfxFrame' in op_str or 'frame' in op_str.lower():
                characteristics.append("Animation Frame Update")
                loop_type = "AnimationFrame"

            # Frame remaining pattern
            if 'dwFrameRemain' in op_str or 'remain' in op_str.lower():
                characteristics.append("Frame Counter Decrement")
                if loop_type != "AnimationFrame":
                    loop_type = "FrameCounter"

            # Direction iteration (8 or 16 directions)
            if 'direction' in op_str.lower() or 'dir' in op_str.lower():
                characteristics.append("Direction Iteration")
                loop_type = "DirectionLoop"

            # Mode/state machine pattern
            if 'mode' in op_str.lower() or 'state' in op_str.lower():
                characteristics.append("State Machine")
                if loop_type == "Generic":
                    loop_type = "StateLoop"

            # Monster/AI pattern
            if 'monster' in op_str.lower() or 'ai' in op_str.lower():
                characteristics.append("Monster/AI")
                if loop_type == "Generic":
                    loop_type = "AILoop"

            # List iteration
            if 'Next' in op_str or 'pNext' in op_str:
                characteristics.append("List Iteration")
                if loop_type == "Generic":
                    loop_type = "ListLoop"

            # Counter pattern (CMP with constant)
            if 'CMP' in current.getMnemonicString():
                match = re.search(r'CMP.*?,\s*(\d+)', op_str)
                if match:
                    count = int(match.group(1))
                    if count in [8, 16]:
                        characteristics.append(f"{count}-Direction Loop")
                        loop_type = "DirectionLoop"
                    elif count in [4, 32, 64]:
                        characteristics.append(f"Fixed Count: {count}")

            current = current.getPrevious()

        return loop_type, characteristics

    def analyze_all_functions(self):
        """Scan all functions for loops"""
        func_count = 0
        total_loops = 0

        funcs = list(self.func_mgr.getFunctions(True))
        total = len(funcs)

        self.log(f"Analyzing {total} functions for loops...")

        for func in funcs:
            func_count += 1

            if func_count % 100 == 0:
                self.log(f"Progress: {func_count}/{total}")

            self.analyze_function(func)

        total_loops = len(self.loops_found)
        return func_count, total_loops

    def print_results(self):
        """Print loop detection results"""
        print("\n" + "="*80)
        print("DIABLO II LOOP AND AI ANALYSIS RESULTS")
        print("="*80 + "\n")

        if not self.loops_found:
            print("[*] No significant loops detected in current analysis scope.\n")
            return

        # Group by loop type
        loops_by_type = {}
        for loop in self.loops_found:
            loop_type = loop['loop_type']
            if loop_type not in loops_by_type:
                loops_by_type[loop_type] = []
            loops_by_type[loop_type].append(loop)

        # Print by type
        for loop_type in sorted(loops_by_type.keys()):
            loops = loops_by_type[loop_type]
            print(f"{loop_type}: {len(loops)} detected")
            print("-" * 80)

            for i, loop in enumerate(sorted(loops, key=lambda x: x['confidence'], reverse=True)[:15]):
                print(f"  Function: {loop['function']}")
                print(f"  Address:  {loop['address']}")
                print(f"  Loop:     {loop['loop_start']} → {loop['loop_end']}")
                print(f"  Type:     {loop['loop_type']}")
                print(f"  Confidence: {loop['confidence']:.0%}")
                print(f"  Characteristics:")
                for char in loop['characteristics']:
                    print(f"    • {char}")
                print()

            if len(loops) > 15:
                print(f"  ... and {len(loops) - 15} more\n")

        # Summary
        print("="*80)
        print(f"SUMMARY: {len(self.loops_found)} loops detected")
        print("="*80 + "\n")

        print("""
ANALYSIS NOTES:

Animation Frame Loops:
  - Process unit animation frames
  - Decrement dwFrameRemain counter
  - Often use tight inner loops for performance
  - Candidates for __d2call custom calling convention

Direction Loops:
  - Iterate over 8 or 16 directions
  - Used for damage spread, targeting, pathfinding
  - Usually fixed iteration count
  - Key optimization target

Monster/AI Loops:
  - Process monster AI decisions
  - Update monster mode/state
  - Move monsters toward targets
  - Often have complex conditional logic

List Iteration Loops:
  - Walk linked lists (monsters, items, etc.)
  - Check next pointer (pNext, pRoomNext, etc.)
  - Common in room processing
  - May benefit from batching optimizations

Performance Optimization Opportunities:
  1. Use __d2call convention for loops with EBX parameters
  2. Consider loop unrolling for 8/16-direction iteration
  3. Cache frequently accessed pointers
  4. Minimize function calls inside loop bodies
  5. Consider SIMD instructions for vector operations
""")

    def generate_ghidra_comments(self):
        """Generate Ghidra comments for loops (requires MCP bridge)"""
        print("\n[*] Generating Ghidra comments for loops...")

        comments = []
        for loop in self.loops_found:
            comment = f"Loop ({loop['loop_type']}): {', '.join(loop['characteristics'][:3])}"
            comments.append({
                'address': loop['loop_start'],
                'comment': comment
            })

        return comments


def main():
    """Main entry point"""
    if currentProgram is None:
        print("[✗] No program loaded in Ghidra!")
        return

    print("[*] Starting Diablo II loop analysis...")
    print(f"[*] Program: {currentProgram.getName()}")

    analyzer = LoopAnalyzer()
    func_count, loop_count = analyzer.analyze_all_functions()

    analyzer.print_results()

    print(f"[✓] Analysis complete!")
    print(f"    Total functions scanned: {func_count}")
    print(f"    Loops detected: {loop_count}")

    # Optional: Generate Ghidra comments
    if loop_count > 0:
        comments = analyzer.generate_ghidra_comments()
        print(f"    Comments to apply: {len(comments)}")
        print("\n[*] Use MCP bridge to apply comments:")
        print("    batch_set_comments(function_address, decompiler_comments=comments)")


if __name__ == "__main__":
    main()
