#!/usr/bin/env python3
"""
GhidraMCP Scripts Configuration

Centralized configuration file for all GhidraMCP scripts.
Contains shared settings, endpoints, timeouts, and other reusable information.

Usage:
    from scripts_config import Config, EndpointConfig, TestConfig
    
    # Get server URL
    server_url = Config.get_server_url()
    
    # Get core endpoints for testing
    core_endpoints = EndpointConfig.CORE_ENDPOINTS
    
    # Get timeout settings
    timeout = Config.REQUEST_TIMEOUT
"""

import os
import sys
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum


class LogLevel(Enum):
    """Logging levels for script output"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class ServerConfig:
    """Server connection configuration"""
    default_host: str = "127.0.0.1"
    default_port: int = 8089
    default_protocol: str = "http"
    request_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class TestConfig:
    """Testing configuration"""
    max_test_items: int = 100
    performance_threshold_ms: float = 5000.0
    concurrent_test_limit: int = 5
    test_data_limit: int = 20
    benchmark_iterations: int = 3


class Config:
    """Main configuration class"""
    
    # Server Configuration
    SERVER = ServerConfig()
    
    # Request Settings
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0
    
    # Output Settings
    DEFAULT_LOG_LEVEL = LogLevel.INFO
    VERBOSE_OUTPUT = False
    JSON_OUTPUT = False
    
    # File Paths
    SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(SCRIPTS_DIR)
    LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
    
    @staticmethod
    def get_server_url(custom_url: Optional[str] = None) -> str:
        """
        Get the server URL from command line args, environment, or default
        
        Args:
            custom_url: Optional custom URL to use
            
        Returns:
            Formatted server URL
        """
        if custom_url:
            return custom_url.rstrip('/') + '/'
        
        # Check command line arguments
        if len(sys.argv) > 1 and sys.argv[1].startswith('http'):
            return sys.argv[1].rstrip('/') + '/'
        
        # Check environment variable
        env_url = os.getenv('GHIDRA_MCP_SERVER_URL')
        if env_url:
            return env_url.rstrip('/') + '/'
        
        # Default
        return f"{Config.SERVER.default_protocol}://{Config.SERVER.default_host}:{Config.SERVER.default_port}/"
    
    @staticmethod
    def ensure_logs_dir():
        """Ensure logs directory exists"""
        os.makedirs(Config.LOGS_DIR, exist_ok=True)
    
    @staticmethod
    def get_log_file(script_name: str) -> str:
        """Get log file path for a script"""
        Config.ensure_logs_dir()
        return os.path.join(Config.LOGS_DIR, f"{script_name}.log")


class EndpointConfig:
    """API endpoint configurations"""
    
    # Core endpoints that should always work
    CORE_ENDPOINTS = [
        ("GET", "/methods", "List available methods"),
        ("GET", "/get_metadata", "Get program metadata"),
        ("GET", "/check_connection", "Check plugin connection"),
        ("GET", "/get_current_address", "Get current address"),
        ("GET", "/list_functions", "List functions"),
        ("GET", "/list_data_types", "List data types"),
        ("GET", "/imports", "List imports"),
        ("GET", "/exports", "List exports"),
        ("GET", "/list_segments", "List memory segments"),
    ]
    
    # Extended endpoints for comprehensive testing
    EXTENDED_ENDPOINTS = [
        ("GET", "/strings", "List strings"),
        ("GET", "/classes", "List classes"),
        ("GET", "/namespaces", "List namespaces"),
        ("GET", "/list_globals", "List global variables"),
        ("GET", "/get_entry_points", "Get entry points"),
    ]
    
    # Data type management endpoints
    DATA_TYPE_ENDPOINTS = [
        ("POST", "/create_struct", "Create structure"),
        ("POST", "/create_enum", "Create enumeration"),
        ("POST", "/create_union", "Create union"),
        ("POST", "/apply_data_type", "Apply data type"),
        ("GET", "/get_struct_layout", "Get structure layout"),
        ("GET", "/get_enum_values", "Get enumeration values"),
        ("GET", "/get_type_size", "Get type size"),
    ]
    
    # Function analysis endpoints
    FUNCTION_ENDPOINTS = [
        ("GET", "/decompile_function", "Decompile function"),
        ("GET", "/disassemble_function", "Disassemble function"),
        ("GET", "/get_function_by_address", "Get function by address"),
        ("GET", "/function_callers", "Get function callers"),
        ("GET", "/function_callees", "Get function callees"),
        ("GET", "/function_call_graph", "Get function call graph"),
        ("GET", "/function_xrefs", "Get function cross-references"),
    ]
    
    # Memory and analysis endpoints
    MEMORY_ENDPOINTS = [
        ("GET", "/xrefs_to", "Get cross-references to address"),
        ("GET", "/xrefs_from", "Get cross-references from address"),
        ("POST", "/set_decompiler_comment", "Set decompiler comment"),
        ("POST", "/set_disassembly_comment", "Set disassembly comment"),
        ("POST", "/create_label", "Create label"),
    ]
    
    # Renaming and modification endpoints
    MODIFICATION_ENDPOINTS = [
        ("POST", "/rename_function", "Rename function"),
        ("POST", "/rename_function_by_address", "Rename function by address"),
        ("POST", "/rename_variable", "Rename variable"),
        ("POST", "/rename_data", "Rename data"),
        ("POST", "/rename_label", "Rename label"),
        ("POST", "/rename_global_variable", "Rename global variable"),
        ("POST", "/set_function_prototype", "Set function prototype"),
        ("POST", "/set_local_variable_type", "Set local variable type"),
    ]
    
    @staticmethod
    def get_all_endpoints() -> List[Tuple[str, str, str]]:
        """Get all endpoints combined"""
        return (EndpointConfig.CORE_ENDPOINTS + 
                EndpointConfig.EXTENDED_ENDPOINTS +
                EndpointConfig.DATA_TYPE_ENDPOINTS +
                EndpointConfig.FUNCTION_ENDPOINTS +
                EndpointConfig.MEMORY_ENDPOINTS +
                EndpointConfig.MODIFICATION_ENDPOINTS)
    
    @staticmethod
    def get_endpoints_by_category(category: str) -> List[Tuple[str, str, str]]:
        """Get endpoints by category name"""
        category_map = {
            "core": EndpointConfig.CORE_ENDPOINTS,
            "extended": EndpointConfig.EXTENDED_ENDPOINTS,
            "data_types": EndpointConfig.DATA_TYPE_ENDPOINTS,
            "functions": EndpointConfig.FUNCTION_ENDPOINTS,
            "memory": EndpointConfig.MEMORY_ENDPOINTS,
            "modification": EndpointConfig.MODIFICATION_ENDPOINTS,
        }
        return category_map.get(category.lower(), [])


class MessageConfig:
    """Standard messages and formatting"""
    
    # Status symbols
    SUCCESS = "✅"
    ERROR = "❌" 
    WARNING = "⚠️"
    INFO = "ℹ️"
    WORKING = "🔧"
    TESTING = "🧪"
    DEPLOYMENT = "🚀"
    HEALTH = "🏥"
    EXAMPLES = "📚"
    
    # Standard messages
    MESSAGES = {
        "server_not_running": "Ghidra MCP server is not running. Please start Ghidra with the GhidraMCP plugin.",
        "plugin_not_loaded": "GhidraMCP plugin is not loaded. Please install and enable the plugin.",
        "no_program_loaded": "No program is loaded in Ghidra. Please load and analyze a binary.",
        "connection_failed": "Failed to connect to server. Check that Ghidra is running with the plugin enabled.",
        "test_passed": "All tests passed successfully.",
        "deployment_needed": "Plugin deployment required. Please install the updated plugin.",
        "ready_for_use": "GhidraMCP is ready for use.",
    }
    
    @staticmethod
    def format_status(success: bool, message: str) -> str:
        """Format a status message with appropriate symbol"""
        symbol = MessageConfig.SUCCESS if success else MessageConfig.ERROR
        return f"{symbol} {message}"
    
    @staticmethod     
    def format_test_result(passed: int, total: int) -> str:
        """Format test results"""
        percentage = (passed / total * 100) if total > 0 else 0
        symbol = MessageConfig.SUCCESS if passed == total else MessageConfig.WARNING
        return f"{symbol} Tests: {passed}/{total} passed ({percentage:.1f}%)"


class SampleDataConfig:
    """Sample data for testing and examples"""
    
    # Sample structure definition
    SAMPLE_STRUCT = {
        "name": "SampleStruct",
        "fields": [
            {"name": "id", "type": "int"},
            {"name": "name", "type": "char[32]"},
            {"name": "flags", "type": "DWORD"},
            {"name": "timestamp", "type": "long"}
        ]
    }
    
    # Sample enumeration definition
    SAMPLE_ENUM = {
        "name": "SampleEnum",
        "values": {
            "STATE_IDLE": 0,
            "STATE_RUNNING": 1,
            "STATE_PAUSED": 2,
            "STATE_STOPPED": 3,
            "STATE_ERROR": 4
        },
        "size": 4
    }
    
    # Sample union definition
    SAMPLE_UNION = {
        "name": "SampleUnion",
        "fields": [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"},
            {"name": "as_bytes", "type": "char[4]"}
        ]
    }
    
    # Common search terms for testing
    SEARCH_TERMS = [
        "main", "init", "start", "end", "get", "set",
        "create", "delete", "open", "close", "read", "write"
    ]


class ValidationConfig:
    """Validation rules and patterns"""
    
    # Address validation patterns
    ADDRESS_PATTERNS = [
        r"^0x[0-9a-fA-F]+$",  # Hex address
        r"^[0-9a-fA-F]+$",    # Hex without prefix
    ]
    
    # Function name patterns
    FUNCTION_NAME_PATTERN = r"^[a-zA-Z_][a-zA-Z0-9_]*$"
    
    # Data type name patterns  
    DATA_TYPE_NAME_PATTERN = r"^[a-zA-Z_][a-zA-Z0-9_]*$"
    
    # Minimum required responses
    MIN_FUNCTIONS = 1
    MIN_DATA_TYPES = 10
    MIN_IMPORTS = 0  # May be 0 for some binaries
    MIN_SEGMENTS = 1
    
    @staticmethod
    def is_valid_address(address: str) -> bool:
        """Validate address format"""
        import re
        return any(re.match(pattern, address) for pattern in ValidationConfig.ADDRESS_PATTERNS)
    
    @staticmethod
    def is_valid_identifier(name: str) -> bool:
        """Validate identifier (function/variable name)"""
        import re
        return bool(re.match(ValidationConfig.FUNCTION_NAME_PATTERN, name))


# Global configuration instance
config = Config()

# Convenience functions for common operations
def get_server_url(custom_url: Optional[str] = None) -> str:
    """Get server URL - convenience function"""
    return Config.get_server_url(custom_url)

def get_core_endpoints() -> List[Tuple[str, str, str]]:
    """Get core endpoints - convenience function"""
    return EndpointConfig.CORE_ENDPOINTS

def get_timeout() -> int:
    """Get request timeout - convenience function"""
    return Config.REQUEST_TIMEOUT

def format_success(message: str) -> str:
    """Format success message - convenience function"""
    return MessageConfig.format_status(True, message)

def format_error(message: str) -> str:
    """Format error message - convenience function"""
    return MessageConfig.format_status(False, message)


if __name__ == "__main__":
    # Configuration test/demo
    print("GhidraMCP Scripts Configuration")
    print("=" * 40)
    print(f"Server URL: {get_server_url()}")
    print(f"Request Timeout: {get_timeout()}s")
    print(f"Core Endpoints: {len(get_core_endpoints())}")
    print(f"All Endpoints: {len(EndpointConfig.get_all_endpoints())}")
    print(f"Project Root: {Config.PROJECT_ROOT}")
    print(f"Logs Directory: {Config.LOGS_DIR}")
    print("\nConfiguration loaded successfully!")