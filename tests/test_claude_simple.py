#!/usr/bin/env python3
"""
Simple Claude Code Test for Ghidra MCP Integration
This script demonstrates a basic example of using Claude Code to analyze and improve code
"""

import subprocess
import os
from pathlib import Path

def test_simple_claude_integration():
    """Simple test of Claude Code integration"""
    
    print("🧪 Testing Claude Code Integration with Ghidra MCP Tools")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not os.path.exists("bridge_mcp_ghidra.py"):
        print("❌ Error: bridge_mcp_ghidra.py not found. Please run from the project root.")
        return
    
    # Test 1: Simple code analysis
    print("\n📋 Test 1: Quick Code Analysis")
    print("-" * 30)
    
    prompt = """
    Please read the bridge_mcp_ghidra.py file and tell me:
    1. How many MCP tools are defined?
    2. What is the most complex tool function?
    3. Are there any obvious security concerns?
    
    Keep your response concise - just 3-4 sentences.
    """
    
    try:
        result = subprocess.run(['claude', '--print', prompt], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Analysis completed:")
            print(result.stdout.strip())
        else:
            print(f"❌ Analysis failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏰ Analysis timed out")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 2: Suggest a small improvement
    print("\n🔧 Test 2: Quick Improvement Suggestion")
    print("-" * 40)
    
    improvement_prompt = """
    Look at the safe_get function in bridge_mcp_ghidra.py and suggest one small, practical improvement that would make it more robust. Just give me a 2-3 line code snippet and a brief explanation.
    """
    
    try:
        result = subprocess.run(['claude', '--print', improvement_prompt], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Improvement suggestion:")
            print(result.stdout.strip())
        else:
            print(f"❌ Suggestion failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏰ Suggestion timed out")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 3: Generate a simple test case
    print("\n🧪 Test 3: Generate Simple Test Case")
    print("-" * 35)
    
    test_prompt = """
    Write a simple pytest test function for the mcp_ghidra_list_functions tool. Just return the test function code, no explanation needed.
    """
    
    try:
        result = subprocess.run(['claude', '--print', test_prompt], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Test case generated:")
            print(result.stdout.strip())
            
            # Save the test case
            with open("claude_generated_test.py", "w") as f:
                f.write("# Auto-generated test case by Claude Code\n\n")
                f.write(result.stdout.strip())
            print("\n📁 Test saved to: claude_generated_test.py")
        else:
            print(f"❌ Test generation failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏰ Test generation timed out")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n✨ Claude Code integration test completed!")
    print("\nNext steps:")
    print("1. Review the full analysis in claude_output_code_review.md")
    print("2. Check new feature ideas in claude_output_feature_suggestions.md") 
    print("3. Run 'python claude_code_integration.py' for comprehensive analysis")
    print("4. Use 'claude --print \"your prompt here\"' for quick queries")

if __name__ == "__main__":
    test_simple_claude_integration()