#!/usr/bin/env python3
"""
Enhanced Test Suite for Ghidra MCP Tools
Generated with Claude Code assistance for comprehensive coverage
"""

import pytest
import subprocess
import requests
import json
import time
from unittest.mock import Mock, patch
import sys
import os

# Add the parent directory to path so we can import the bridge
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the bridge module
try:
    import bridge_mcp_ghidra as bridge
except ImportError as e:
    pytest.skip(f"Could not import bridge_mcp_ghidra: {e}", allow_module_level=True)

class TestInputValidation:
    """Test input validation functions"""
    
    def test_validate_hex_address_valid(self):
        """Test hex address validation with valid addresses"""
        valid_addresses = [
            "0x1400010a0",
            "0x0",
            "0xFFFFFFFF",
            "0xdeadbeef",
            "0xCAFEBABE"
        ]
        
        for addr in valid_addresses:
            assert bridge.validate_hex_address(addr), f"Should accept valid address: {addr}"
    
    def test_validate_hex_address_invalid(self):
        """Test hex address validation with invalid addresses"""
        invalid_addresses = [
            "1400010a0",      # Missing 0x prefix
            "0x",             # Empty hex part
            "0xGGGG",         # Invalid hex characters
            "0x 1234",        # Space in address
            "",               # Empty string
            "not_hex",        # Not hex at all
            None              # None value
        ]
        
        for addr in invalid_addresses:
            assert not bridge.validate_hex_address(addr), f"Should reject invalid address: {addr}"
    
    def test_validate_function_name_valid(self):
        """Test function name validation with valid names"""
        valid_names = [
            "main",
            "sub_401000",
            "_start",
            "function_123",
            "MyFunction",
            "test_func_name"
        ]
        
        for name in valid_names:
            assert bridge.validate_function_name(name), f"Should accept valid name: {name}"
    
    def test_validate_function_name_invalid(self):
        """Test function name validation with invalid names"""
        invalid_names = [
            "123function",    # Starts with number
            "func-name",      # Contains dash
            "func name",      # Contains space
            "",               # Empty string
            "func@name",      # Contains special char
            None              # None value
        ]
        
        for name in invalid_names:
            assert not bridge.validate_function_name(name), f"Should reject invalid name: {name}"
    
    def test_validate_server_url_valid(self):
        """Test server URL validation with valid URLs"""
        valid_urls = [
            "http://127.0.0.1:8080",
            "http://localhost:8089",
            "http://192.168.1.100:8080",
            "http://10.0.0.1:8080"
        ]
        
        for url in valid_urls:
            assert bridge.validate_server_url(url), f"Should accept valid URL: {url}"
    
    def test_validate_server_url_invalid(self):
        """Test server URL validation with invalid/unsafe URLs"""
        invalid_urls = [
            "http://google.com",          # External domain
            "http://malware.example.com", # Malicious domain
            "ftp://127.0.0.1",          # Non-HTTP protocol
            "",                          # Empty string
            "not_a_url"                 # Invalid URL format
        ]
        
        for url in invalid_urls:
            assert not bridge.validate_server_url(url), f"Should reject unsafe URL: {url}"


class TestErrorHandling:
    """Test enhanced error handling"""
    
    @patch('bridge_mcp_ghidra.session.get')
    def test_safe_get_server_error_retry(self, mock_get):
        """Test that server errors trigger retry logic"""
        # Mock server error response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.ok = False
        mock_get.return_value = mock_response
        
        result = bridge.safe_get("test_endpoint", retries=2)
        
        # Should have tried twice (initial + 1 retry)
        assert mock_get.call_count == 2
        assert any("Server error" in line for line in result)
    
    @patch('bridge_mcp_ghidra.session.get')
    def test_safe_get_timeout_handling(self, mock_get):
        """Test timeout handling"""
        # Mock timeout exception
        mock_get.side_effect = requests.exceptions.Timeout()
        
        result = bridge.safe_get("test_endpoint", retries=2)
        
        assert mock_get.call_count == 2  # Should retry on timeout
        assert any("Timeout" in line for line in result)
    
    @patch('bridge_mcp_ghidra.session.get')
    def test_safe_get_success_response(self, mock_get):
        """Test successful response handling"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.text = "line1\nline2\nline3"
        mock_get.return_value = mock_response
        
        result = bridge.safe_get("test_endpoint")
        
        assert mock_get.call_count == 1
        assert result == ["line1", "line2", "line3"]


class TestValidationIntegration:
    """Test that validation is properly integrated into MCP tools"""
    
    def test_get_xrefs_to_validation(self):
        """Test that get_xrefs_to validates addresses"""
        with pytest.raises(bridge.GhidraValidationError):
            bridge.get_xrefs_to("invalid_address")
    
    def test_find_similar_functions_validation(self):
        """Test that find_similar_functions validates function names"""
        with pytest.raises(bridge.GhidraValidationError):
            bridge.mcp_ghidra_find_similar_functions("123invalid")
    
    def test_batch_decompile_validation(self):
        """Test that batch_decompile validates all function names"""
        with pytest.raises(bridge.GhidraValidationError):
            bridge.mcp_ghidra_batch_decompile(["valid_func", "123invalid"])


class TestNewEndpoints:
    """Test the new enhanced endpoints"""
    
    @patch('bridge_mcp_ghidra.safe_get')
    def test_detect_crypto_constants(self, mock_safe_get):
        """Test crypto constants detection endpoint"""
        mock_safe_get.return_value = ["AES S-box found at 0x401000"]
        
        result = bridge.mcp_ghidra_detect_crypto_constants()
        
        mock_safe_get.assert_called_once_with("detect_crypto_constants")
        assert result == ["AES S-box found at 0x401000"]
    
    @patch('bridge_mcp_ghidra.safe_get')
    def test_search_byte_patterns(self, mock_safe_get):
        """Test byte pattern search endpoint"""
        mock_safe_get.return_value = ["Pattern found at 0x401000"]
        
        result = bridge.mcp_ghidra_search_byte_patterns("E8 ?? ?? ?? ??", "FF 00 00 00 00")
        
        mock_safe_get.assert_called_once_with("search_byte_patterns", {
            "pattern": "E8 ?? ?? ?? ??",
            "mask": "FF 00 00 00 00"
        })
        assert result == ["Pattern found at 0x401000"]
    
    @patch('bridge_mcp_ghidra.safe_get')
    def test_extract_iocs(self, mock_safe_get):
        """Test IOC extraction endpoint"""
        mock_safe_get.return_value = {"ips": ["192.168.1.1"], "urls": ["http://evil.com"]}
        
        result = bridge.mcp_ghidra_extract_iocs()
        
        mock_safe_get.assert_called_once_with("extract_iocs")
        assert result == {"ips": ["192.168.1.1"], "urls": ["http://evil.com"]}


class TestPerformanceAndBatching:
    """Test performance improvements and batch operations"""
    
    @patch('bridge_mcp_ghidra.safe_get')
    def test_batch_decompile(self, mock_safe_get):
        """Test batch decompilation"""
        functions = ["main", "sub_401000", "helper_func"]
        mock_safe_get.return_value = {
            "main": "int main() { return 0; }",
            "sub_401000": "void sub_401000() { }",
            "helper_func": "int helper_func(int x) { return x + 1; }"
        }
        
        result = bridge.mcp_ghidra_batch_decompile(functions)
        
        mock_safe_get.assert_called_once_with("batch_decompile", {
            "functions": "main,sub_401000,helper_func"
        })
        assert len(result) == 3
    
    @patch('bridge_mcp_ghidra.safe_get')
    def test_batch_rename_functions(self, mock_safe_get):
        """Test batch function renaming"""
        renames = {"old_name": "new_name", "func_1": "better_name"}
        mock_safe_get.return_value = {"success": True, "renamed": 2}
        
        result = bridge.mcp_ghidra_batch_rename_functions(renames)
        
        mock_safe_get.assert_called_once()
        assert result == {"success": True, "renamed": 2}


class TestIntegrationWithGhidraServer:
    """Integration tests that require a running Ghidra server"""
    
    @pytest.fixture(autouse=True)
    def check_server_available(self):
        """Check if Ghidra server is available before running integration tests"""
        try:
            response = requests.get(f"{bridge.ghidra_server_url}metadata", timeout=5)
            if not response.ok:
                pytest.skip("Ghidra server not available for integration tests")
        except (requests.exceptions.RequestException, requests.exceptions.Timeout):
            pytest.skip("Ghidra server not available for integration tests")
    
    def test_list_functions_integration(self):
        """Integration test for listing functions"""
        result = bridge.list_functions()
        assert isinstance(result, list)
        # Should return some functions if a program is loaded
    
    def test_get_metadata_integration(self):
        """Integration test for getting metadata"""
        result = bridge.get_metadata()
        assert isinstance(result, list)
        # Should return metadata information


class TestSecurityFeatures:
    """Test security enhancements"""
    
    def test_server_url_restriction(self):
        """Test that server URLs are restricted to safe addresses"""
        # This test ensures only local/private addresses are allowed
        unsafe_urls = [
            "http://attacker.com:8080",
            "http://8.8.8.8:8080",
            "https://malware.example.com"
        ]
        
        for url in unsafe_urls:
            assert not bridge.validate_server_url(url)
    
    def test_input_sanitization(self):
        """Test that inputs are properly sanitized"""
        # Test SQL injection attempts
        malicious_inputs = [
            "'; DROP TABLE functions; --",
            "0x401000 OR 1=1",
            "<script>alert('xss')</script>"
        ]
        
        for malicious_input in malicious_inputs:
            # Should not validate as proper hex address
            assert not bridge.validate_hex_address(malicious_input)


def run_performance_benchmarks():
    """Run performance benchmarks for key operations"""
    print("\n=== Performance Benchmarks ===")
    
    operations = [
        ("list_functions", bridge.list_functions, []),
        ("get_metadata", bridge.get_metadata, []),
    ]
    
    for name, func, args in operations:
        try:
            start_time = time.time()
            result = func(*args)
            duration = time.time() - start_time
            print(f"{name}: {duration:.3f}s ({len(result) if isinstance(result, list) else 'N/A'} items)")
        except Exception as e:
            print(f"{name}: Failed - {e}")


if __name__ == "__main__":
    # Run tests
    print("Running enhanced test suite...")
    pytest.main([__file__, "-v", "--tb=short"])
    
    # Run performance benchmarks
    run_performance_benchmarks()
    
    print("\n✅ Enhanced test suite completed!")
    print("Key improvements:")
    print("- Input validation testing")
    print("- Error handling verification")
    print("- Security feature testing")
    print("- New endpoint validation")
    print("- Performance benchmarking")