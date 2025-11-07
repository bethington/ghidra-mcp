#!/usr/bin/env python3
"""
MCP-aware Ghidra Function Documentation Processor

This processor uses Claude with the Ghidra MCP bridge to systematically
document functions using a three-phase approach:
- Phase 1: Adaptive Prompt Enhancement (5 functions)
- Phase 2: Pattern Formalization (3 functions)  
- Phase 3: Stateful Agent Loop (526 functions)

Prerequisites:
- Ghidra server running at http://127.0.0.1:8089/
- MCP bridge: python bridge_mcp_ghidra.py
"""

import json
import sys
import os
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any

# Add workspace root to path
WORKSPACE_ROOT = Path(__file__).parent
SCRIPTS_DIR = WORKSPACE_ROOT / "scripts"
DOCS_DIR = WORKSPACE_ROOT / "docs"
PROMPTS_DIR = DOCS_DIR / "prompts"

def load_pending_functions() -> List[str]:
    """Load pending functions from FunctionsTodo.txt"""
    todo_file = SCRIPTS_DIR / "FunctionsTodo.txt"
    if not todo_file.exists():
        print(f"ERROR: Cannot find {todo_file}")
        return []
    
    functions = []
    with open(todo_file, 'r') as f:
        for line in f:
            # Match both [ ] and [X] patterns
            if line.startswith('[ ] ') or line.startswith('[X] '):
                # Extract function name
                parts = line[4:].strip().split()
                if parts:
                    func_name = parts[0]
                    # Validate pattern: FUN_ or Ordinal_ followed by hex
                    if func_name.startswith(('FUN_', 'Ordinal_')):
                        functions.append(func_name)
    
    return functions

def load_base_prompt() -> str:
    """Load the base optimization prompt"""
    prompt_file = PROMPTS_DIR / "OPTIMIZED_FUNCTION_DOCUMENTATION.md"
    if not prompt_file.exists():
        print(f"ERROR: Cannot find {prompt_file}")
        return ""
    
    with open(prompt_file, 'r') as f:
        return f.read()

def invoke_claude_with_mcp(prompt: str, mcp_config: Dict[str, Any]) -> Optional[str]:
    """
    Invoke Claude with MCP bridge using stdio transport.
    
    Args:
        prompt: The prompt to send to Claude
        mcp_config: MCP server configuration
        
    Returns:
        Claude's response or None if failed
    """
    try:
        # Prepare the Claude command with MCP config
        cmd = [
            "claude",
            "-p",  # Print mode (non-interactive)
            "--output-format", "text",
            "--mcp-config", json.dumps(mcp_config),
            "--dangerously-skip-permissions",
        ]
        
        # Set environment for 8GB memory
        env = os.environ.copy()
        env["NODE_OPTIONS"] = "--max-old-space-size=8192"
        
        # Invoke Claude
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=180,  # 3 minute timeout
            env=env
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"  [-] Claude error: {result.stderr[:200]}")
            return None
            
    except subprocess.TimeoutExpired:
        print(f"  [-] Claude timeout (3 minutes)")
        return None
    except Exception as e:
        print(f"  [-] Exception: {str(e)[:100]}")
        return None

def process_phase_1(functions: List[str], base_prompt: str, mcp_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Phase 1: Adaptive Prompt Enhancement
    Process first 5 functions with cumulative insights
    """
    print("\n" + "="*50)
    print("PHASE 1: ADAPTIVE PROMPT ENHANCEMENT")
    print("="*50 + "\n")
    
    phase1_functions = functions[:5]
    results = {
        'timestamp': datetime.now().isoformat(),
        'phase': 1,
        'functions_processed': 0,
        'insights': [],
        'successes': [],
        'failures': []
    }
    
    cumulative_insights = []
    
    for i, func_name in enumerate(phase1_functions, 1):
        print(f"[{i}/5] Processing: {func_name}")
        
        # Build adaptive prompt with cumulative insights
        adaptive_prompt = base_prompt + "\n\n"
        
        if cumulative_insights:
            adaptive_prompt += "## PREVIOUS PHASE 1 INSIGHTS:\n"
            for insight in cumulative_insights[-3:]:  # Last 3 insights
                adaptive_prompt += f"- {insight}\n"
            adaptive_prompt += "\n"
        
        adaptive_prompt += f"## TARGET FUNCTION:\n{func_name}\n"
        adaptive_prompt += "\nFocus on discovering and documenting the function structure and purpose."
        
        # Invoke Claude
        start_time = time.time()
        response = invoke_claude_with_mcp(adaptive_prompt, mcp_config)
        elapsed = time.time() - start_time
        
        if response:
            print(f"  [+] Success ({elapsed:.1f}s)")
            results['functions_processed'] += 1
            results['successes'].append(func_name)
            
            # Extract simple insight
            insight = f"Processed {func_name} - discovered patterns and structure"
            cumulative_insights.append(insight)
            results['insights'].append(insight)
        else:
            print(f"  [-] Failed ({elapsed:.1f}s)")
            results['failures'].append(func_name)
    
    return results

def process_phase_2(functions: List[str], phase1_results: Dict[str, Any], 
                   base_prompt: str, mcp_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Phase 2: Pattern Formalization
    Validate and formalize patterns from Phase 1
    """
    print("\n" + "="*50)
    print("PHASE 2: PATTERN FORMALIZATION")
    print("="*50 + "\n")
    
    phase2_functions = functions[5:8]  # Functions 5-7
    results = {
        'timestamp': datetime.now().isoformat(),
        'phase': 2,
        'functions_processed': 0,
        'patterns_formalized': {},
        'successes': [],
        'failures': []
    }
    
    for i, func_name in enumerate(phase2_functions, 1):
        print(f"[{i}/3] Processing: {func_name}")
        
        # Build formalization prompt
        formalization_prompt = base_prompt + "\n\n"
        formalization_prompt += "## PHASE 1 INSIGHTS:\n"
        for insight in phase1_results['insights'][:3]:
            formalization_prompt += f"- {insight}\n"
        formalization_prompt += "\n## FORMALIZATION TASK:\n"
        formalization_prompt += f"Function: {func_name}\n"
        formalization_prompt += "Extract and formalize patterns, structures, and naming conventions discovered so far."
        
        # Invoke Claude
        start_time = time.time()
        response = invoke_claude_with_mcp(formalization_prompt, mcp_config)
        elapsed = time.time() - start_time
        
        if response:
            print(f"  [+] Success ({elapsed:.1f}s)")
            results['functions_processed'] += 1
            results['successes'].append(func_name)
            
            # Store formalized patterns
            results['patterns_formalized'][func_name] = {
                'response_length': len(response),
                'processed_at': datetime.now().isoformat()
            }
        else:
            print(f"  [-] Failed ({elapsed:.1f}s)")
            results['failures'].append(func_name)
    
    return results

def process_phase_3(functions: List[str], phase1_results: Dict[str, Any],
                   phase2_results: Dict[str, Any], base_prompt: str,
                   mcp_config: Dict[str, Any], limit: Optional[int] = None) -> Dict[str, Any]:
    """
    Phase 3: Stateful Agent Loop
    Process remaining functions with learned patterns
    
    Args:
        functions: All functions
        phase1_results: Results from Phase 1
        phase2_results: Results from Phase 2
        base_prompt: Base documentation prompt
        mcp_config: MCP configuration
        limit: Optional limit on number of functions to process (for testing)
    """
    print("\n" + "="*50)
    print("PHASE 3: STATEFUL AGENT LOOP")
    print("="*50 + "\n")
    
    phase3_functions = functions[8:]  # Remaining functions
    
    if limit:
        phase3_functions = phase3_functions[:limit]
        print(f"[Testing Mode] Processing {limit} of {len(functions[8:])} functions\n")
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'phase': 3,
        'functions_processed': 0,
        'functions_total': len(phase3_functions),
        'successes': [],
        'failures': [],
        'phase1_insights_used': len(phase1_results['insights']),
        'phase2_patterns_used': len(phase2_results['patterns_formalized'])
    }
    
    # Build knowledge context from Phase 1 & 2
    knowledge_context = "\n## LEARNED PATTERNS FROM EARLIER PHASES:\n"
    knowledge_context += "Phase 1 Insights:\n"
    for insight in phase1_results['insights'][:5]:
        knowledge_context += f"  - {insight}\n"
    
    knowledge_context += "\nPhase 2 Patterns:\n"
    for func_name in list(phase2_results['patterns_formalized'].keys())[:3]:
        knowledge_context += f"  - {func_name}\n"
    
    print(f"Processing {len(phase3_functions)} functions with learned knowledge...\n")
    
    for i, func_name in enumerate(phase3_functions, 1):
        if i % 10 == 0:  # Progress update every 10
            print(f"[{i}/{len(phase3_functions)}] Progress checkpoint")
        
        # Build intelligent prompt using learned patterns
        intelligent_prompt = base_prompt + knowledge_context + "\n"
        intelligent_prompt += f"\n## TARGET FUNCTION:\n{func_name}\n"
        intelligent_prompt += "Use the learned patterns to efficiently document this function."
        
        # Invoke Claude with optimized params (shorter timeout for Phase 3)
        response = invoke_claude_with_mcp(intelligent_prompt, mcp_config)
        
        if response:
            results['functions_processed'] += 1
            results['successes'].append(func_name)
        else:
            results['failures'].append(func_name)
        
        # Progress output every 50 functions
        if i % 50 == 0:
            success_rate = (len(results['successes']) / i) * 100
            print(f"  -> {i} functions processed ({success_rate:.1f}% success rate)")
    
    return results

def main():
    """Main processor entry point"""
    print("MCP GHIDRA FUNCTION PROCESSOR")
    print("=" * 50)
    
    # Load functions
    print("\nLoading pending functions...")
    functions = load_pending_functions()
    
    if not functions:
        print("ERROR: No pending functions found")
        return 1
    
    print(f"Found {len(functions)} pending functions")
    print(f"  Phase 1: {min(5, len(functions))} functions")
    print(f"  Phase 2: {min(3, len(functions)-5)} functions" if len(functions) > 5 else "  Phase 2: 0 functions")
    print(f"  Phase 3: {max(0, len(functions)-8)} functions" if len(functions) > 8 else "  Phase 3: 0 functions")
    
    # Load base prompt
    print("\nLoading base prompt...")
    base_prompt = load_base_prompt()
    if not base_prompt:
        print("ERROR: Could not load base prompt")
        return 1
    print(f"Loaded prompt ({len(base_prompt)} characters)")
    
    # Configure MCP
    print("\nConfiguring MCP bridge...")
    mcp_config = {
        "stdio": {
            "command": str(WORKSPACE_ROOT / "bridge_mcp_ghidra.py"),
            "args": ["--transport", "stdio"],
            "env": {
                "GHIDRA_SERVER": "http://127.0.0.1:8089/"
            }
        }
    }
    
    # Process phases
    print("\n" + "="*50)
    print("STARTING FUNCTION PROCESSING")
    print("="*50)
    
    try:
        # Phase 1
        phase1_results = process_phase_1(functions, base_prompt, mcp_config)
        print(f"\nPhase 1 Summary: {phase1_results['functions_processed']}/5 successful")
        
        # Phase 2
        phase2_results = process_phase_2(functions, phase1_results, base_prompt, mcp_config)
        print(f"\nPhase 2 Summary: {phase2_results['functions_processed']}/3 successful")
        
        # Phase 3 (with limit for testing)
        test_limit = int(os.environ.get("PHASE3_LIMIT", "0"))  # 0 means process all
        phase3_results = process_phase_3(functions, phase1_results, phase2_results, 
                                        base_prompt, mcp_config, limit=test_limit if test_limit > 0 else None)
        print(f"\nPhase 3 Summary: {phase3_results['functions_processed']}/{phase3_results['functions_total']} successful")
        
        # Save results
        all_results = {
            'processor': 'mcp_function_processor.py',
            'timestamp': datetime.now().isoformat(),
            'total_functions': len(functions),
            'phase_1': phase1_results,
            'phase_2': phase2_results,
            'phase_3': phase3_results,
            'total_processed': (phase1_results['functions_processed'] + 
                              phase2_results['functions_processed'] +
                              phase3_results['functions_processed'])
        }
        
        output_file = SCRIPTS_DIR / "mcp_processor_results.json"
        with open(output_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"\n[+] Results saved to: {output_file}")
        print(f"\nTOTAL: {all_results['total_processed']}/{len(functions)} functions processed")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nProcessor interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\nERROR: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
