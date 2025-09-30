#!/usr/bin/env python3
"""
Ghidra MCP Documentation Evolution Demo

This script demonstrates the complete evolutionary system for improving
Ghidra binary analysis documentation using Claude Code AI.
"""

import sys
import os
import time
from evolve_ghidra_documentation import GhidraDocumentationEvolver
import logging

def demo_evolution_system():
    """Demonstrate the evolution system capabilities"""
    print("=" * 80)
    print("GHIDRA MCP DOCUMENTATION EVOLUTION DEMO")
    print("=" * 80)
    
    print("\n🚀 This system continuously evolves:")
    print("   1. AI prompts for better Ghidra binary analysis documentation")
    print("   2. MCP tools based on real-world usage patterns")
    print("   3. Analysis quality through iterative improvement")
    
    print("\n📋 Current MCP Tools Available:")
    
    # Show current tools from bridge
    try:
        import bridge_mcp_ghidra as bridge
        tools = [name for name in dir(bridge) if name.startswith('mcp_ghidra_')]
        
        print(f"   • {len(tools)} Ghidra MCP tools available")
        print("   • Enhanced malware analysis capabilities")
        print("   • Performance optimized with connection pooling")
        print("   • Comprehensive error handling and validation")
        
        # Show some example tools
        example_tools = [
            "mcp_ghidra_decrypt_strings_auto - Automatically decrypt obfuscated strings",
            "mcp_ghidra_analyze_api_call_chains - Detect malicious API patterns", 
            "mcp_ghidra_extract_iocs_with_context - Enhanced IOC extraction",
            "mcp_ghidra_detect_malware_behaviors - Identify malware techniques"
        ]
        
        print("\n   Example Advanced Tools:")
        for tool in example_tools:
            print(f"   • {tool}")
            
    except ImportError:
        print("   • Bridge module not available for inspection")
    
    print("\n🧠 AI Evolution Process:")
    print("   1. Evaluate current documentation quality using Claude")
    print("   2. Identify strengths, weaknesses, and improvement areas")
    print("   3. Evolve prompts to address specific deficiencies") 
    print("   4. Suggest new MCP tools and enhancements")
    print("   5. Track performance trends over time")
    
    print("\n⚙️  Starting Evolution Cycle...")
    print("-" * 50)
    
    # Run a demonstration evolution cycle
    evolver = GhidraDocumentationEvolver()
    
    start_time = time.time()
    results = evolver.run_evolution_cycle()
    duration = time.time() - start_time
    
    print(f"\n✅ Evolution cycle completed in {duration:.1f} seconds")
    
    # Show results
    if results.get('status') == 'completed':
        print("\n📊 Results Summary:")
        summary = results.get('summary', {})
        
        print(f"   • Prompt Evolution: {'✅ Success' if summary.get('prompt_evolved') else '❌ Failed'}")
        print(f"   • Tool Improvements: {summary.get('improvements_suggested', 0)} suggestions generated")
        print(f"   • Documentation Quality: {summary.get('documentation_quality', 'N/A')}")
        
        # Show cycle history
        history_size = len(evolver.evolution_history.get('cycles', []))
        print(f"   • Total Evolution Cycles: {history_size}")
        
        print("\n📁 Generated Files:")
        print(f"   • Evolution report: evolution_results/cycle_report_{results['cycle_id']}.md")
        print(f"   • Updated prompt: prompts/ghidra_documentation_prompt.md")
        print(f"   • Evolution history: evolution_history.json")
        
        # Show next steps
        print("\n🎯 Next Steps:")
        print("   1. Review the evolved documentation prompt")
        print("   2. Test with real malware samples")
        print("   3. Implement suggested tool improvements") 
        print("   4. Run additional evolution cycles")
        print("   5. Monitor improvement trends")
        
    else:
        print(f"\n❌ Evolution cycle failed: {results.get('error', 'Unknown error')}")
    
    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
    
    print("\n💡 To use the system:")
    print(f"   python evolve_ghidra_documentation.py --cycles 1")
    print(f"   python evolve_ghidra_documentation.py --binary sample.exe --cycles 3")
    
    return results

def show_current_prompt():
    """Show the current documentation prompt"""
    print("\n📝 Current Documentation Prompt:")
    print("-" * 50)
    
    try:
        evolver = GhidraDocumentationEvolver()
        current_prompt = evolver._get_current_documentation_prompt()
        
        # Show first few lines
        lines = current_prompt.split('\n')
        for i, line in enumerate(lines[:20]):
            print(f"   {line}")
        
        if len(lines) > 20:
            print(f"   ... ({len(lines) - 20} more lines)")
            
        print(f"\n📏 Total prompt length: {len(current_prompt)} characters")
        
    except Exception as e:
        print(f"   Error reading prompt: {e}")

def main():
    """Main demo function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--show-prompt":
        show_current_prompt()
    else:
        demo_evolution_system()

if __name__ == "__main__":
    main()