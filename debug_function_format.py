#!/usr/bin/env python3
"""
Quick test to see the actual function list format from Ghidra MCP
"""

import requests
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_function_format():
    """Test to see the actual function list format."""
    try:
        # Test connection first
        response = requests.get("http://127.0.0.1:8080/check_connection", timeout=10)
        if response.status_code != 200:
            logger.error("MCP plugin not accessible")
            return
            
        logger.info("✅ MCP plugin is accessible")
        
        # Get function list
        response = requests.get("http://127.0.0.1:8080/functions?limit=10", timeout=30)
        if response.status_code == 200:
            functions_text = response.text.strip()
            logger.info("Function list format:")
            lines = functions_text.split('\n')
            for i, line in enumerate(lines[:10]):  # Show first 10 lines
                logger.info(f"  [{i}]: '{line}'")
        else:
            logger.error(f"Failed to get functions: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    test_function_format()