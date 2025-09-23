"""
Test fixtures and utilities for GhidraMCP test suite.

This module provides common test data, utilities, and helper functions
used across different test categories following testing best practices.
"""
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import random
import string


class ComplexityLevel(Enum):
    """Test complexity levels."""
    SIMPLE = "simple"
    MEDIUM = "medium"
    COMPLEX = "complex"
    STRESS = "stress"


@dataclass
class BinaryTestInfo:
    """Information about a test binary with comprehensive metadata."""
    name: str
    path: str
    architecture: str
    expected_functions: List[str] = field(default_factory=list)
    expected_imports: List[str] = field(default_factory=list)
    expected_exports: List[str] = field(default_factory=list)
    base_address: str = "0x400000"
    entry_point: str = "0x401000"
    file_size: int = 0
    sections: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class TestEndpointConfig:
    """Test endpoint configuration."""
    path: str
    method: str = "GET"
    requires_params: bool = False
    expected_status: int = 200
    timeout: int = 30
    description: str = ""


class TestDataGenerator:
    """Generates test data for various test scenarios using best practices."""
    
    @staticmethod
    def generate_unique_name(prefix: str = "test") -> str:
        """Generate unique test names to avoid conflicts."""
        timestamp = str(int(time.time()))
        unique_id = str(uuid.uuid4())[:8]
        return f"{prefix}_{timestamp}_{unique_id}"
    
    @staticmethod
    def generate_struct_fields(complexity: ComplexityLevel = ComplexityLevel.SIMPLE) -> List[Dict[str, str]]:
        """Generate struct field definitions with various complexity levels."""
        
        base_fields = [
            {"name": "id", "type": "int"},
            {"name": "value", "type": "int"}
        ]
        
        medium_fields = [
            {"name": "header", "type": "int"},
            {"name": "data", "type": "char[64]"},
            {"name": "flags", "type": "DWORD"},
            {"name": "checksum", "type": "short"}
        ]
        
        complex_fields = [
            {"name": "magic", "type": "DWORD"},
            {"name": "version", "type": "short"},
            {"name": "reserved", "type": "short"},
            {"name": "data_offset", "type": "DWORD"},
            {"name": "data_size", "type": "DWORD"},
            {"name": "flags", "type": "DWORD"},
            {"name": "checksum", "type": "DWORD"},
            {"name": "timestamp", "type": "QWORD"},
            {"name": "user_data", "type": "char[256]"},
            {"name": "padding", "type": "char[16]"}
        ]
        
        stress_fields = complex_fields + [
            {"name": f"field_{i}", "type": random.choice(["int", "short", "char", "DWORD"])}
            for i in range(20)
        ]
        
        if complexity == ComplexityLevel.SIMPLE:
            return base_fields
        elif complexity == ComplexityLevel.MEDIUM:
            return medium_fields
        elif complexity == ComplexityLevel.COMPLEX:
            return complex_fields
        elif complexity == ComplexityLevel.STRESS:
            return stress_fields
        
        return base_fields
    
    @staticmethod
    def generate_enum_values(enum_type: str = "status") -> Dict[str, int]:
        """Generate enum value definitions for different types."""
        
        enum_templates = {
            "status": {
                "STATUS_SUCCESS": 0,
                "STATUS_ERROR": 1,
                "STATUS_PENDING": 2,
                "STATUS_TIMEOUT": 3
            },
            "flags": {
                "FLAG_NONE": 0,
                "FLAG_READ": 1,
                "FLAG_WRITE": 2,
                "FLAG_EXECUTE": 4,
                "FLAG_ALL": 7
            },
            "error_codes": {
                "E_SUCCESS": 0,
                "E_INVALID_PARAM": -1,
                "E_OUT_OF_MEMORY": -2,
                "E_ACCESS_DENIED": -3,
                "E_NOT_FOUND": -4
            }
        }
        
        return enum_templates.get(enum_type, enum_templates["status"])
    
    @staticmethod
    def generate_union_fields() -> List[Dict[str, str]]:
        """Generate union field definitions."""
        return [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"},
            {"name": "as_bytes", "type": "char[4]"},
            {"name": "as_short", "type": "short[2]"}
        ]
    
    @staticmethod
    def generate_test_addresses(count: int = 10) -> List[str]:
        """Generate test addresses in hex format."""
        base_address = 0x401000
        return [f"0x{base_address + (i * 0x10):x}" for i in range(count)]
    
    @staticmethod
    def generate_function_prototypes() -> List[str]:
        """Generate realistic function prototypes for testing."""
        return [
            "int main(int argc, char** argv)",
            "void* malloc(size_t size)",
            "int printf(const char* format, ...)",
            "FILE* fopen(const char* filename, const char* mode)",
            "int strcmp(const char* str1, const char* str2)",
            "size_t strlen(const char* str)",
            "void memcpy(void* dest, const void* src, size_t n)",
            "int atoi(const char* str)"
        ]


class MockDataProvider:
    """Provides mock data for testing without requiring actual Ghidra instance."""
    
    @staticmethod
    def get_mock_metadata() -> Dict[str, Any]:
        """Mock program metadata."""
        return {
            "name": "test_program.exe",
            "architecture": "x86:LE:32:default",
            "base_address": "0x400000",
            "entry_point": "0x401000",
            "language": "x86:LE:32:default",
            "compiler": "windows",
            "file_format": "Portable Executable (PE)"
        }
    
    @staticmethod
    def get_mock_functions(count: int = 10) -> List[Dict[str, Any]]:
        """Mock function list."""
        functions = []
        base_addr = 0x401000
        
        function_names = [
            "main", "WinMain", "DllMain", "init", "cleanup",
            "process_data", "validate_input", "error_handler",
            "get_version", "allocate_memory"
        ]
        
        for i in range(min(count, len(function_names))):
            functions.append({
                "name": function_names[i],
                "address": f"0x{base_addr + (i * 0x100):x}",
                "size": random.randint(50, 500),
                "entry_point": f"0x{base_addr + (i * 0x100):x}"
            })
        
        return functions
    
    @staticmethod
    def get_mock_strings(count: int = 20) -> List[Dict[str, Any]]:
        """Mock string list."""
        sample_strings = [
            "Hello, World!", "Error: Invalid parameter", "Debug mode enabled",
            "Copyright 2025", "Version 1.0.0", "Configuration loaded",
            "Processing complete", "Access denied", "File not found",
            "Memory allocation failed", "Success", "Warning: Low memory",
            "Connecting to server...", "Operation cancelled", "Invalid format",
            "Database connection error", "Backup created", "User authenticated",
            "Session expired", "Data corrupted"
        ]
        
        strings = []
        base_addr = 0x404000
        
        for i in range(min(count, len(sample_strings))):
            strings.append({
                "address": f"0x{base_addr + (i * 0x20):x}",
                "value": sample_strings[i],
                "length": len(sample_strings[i]) + 1,
                "encoding": "ascii"
            })
        
        return strings


class TestValidators:
    """Validation utilities for test assertions."""
    
    @staticmethod
    def validate_address_format(address: str) -> bool:
        """Validate that address is in proper hex format."""
        if address is None or not isinstance(address, str):
            return False
        
        try:
            if not address.startswith('0x'):
                return False
            if len(address) <= 2:  # Must have at least one hex digit after 0x
                return False
            int(address[2:], 16)
            return True
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def validate_struct_fields(fields: List[Dict[str, str]]) -> bool:
        """Validate struct field definitions."""
        if fields is None:
            return False
        
        if not isinstance(fields, list):
            return False
        
        # Empty list is valid for struct fields
        
        required_keys = {"name", "type"}
        
        for field in fields:
            if not isinstance(field, dict):
                return False
            if not required_keys.issubset(field.keys()):
                return False
            if not field["name"] or not field["type"]:
                return False
        
        return True
    
    @staticmethod
    def validate_enum_values(enum_values: Dict[str, int]) -> bool:
        """Validate enum value definitions."""
        if not isinstance(enum_values, dict):
            return False
        
        # Empty dict is valid for enum values
        
        # Check that all keys are strings and values are integers
        for name, value in enum_values.items():
            if not isinstance(name, str) or not isinstance(value, int):
                return False
            if not name:  # Empty string names are invalid
                return False
        
        return True
    
    @staticmethod
    def validate_response_structure(response_data: Any, expected_fields: List[str]) -> bool:
        """Validate that response contains expected fields."""
        if not isinstance(response_data, dict):
            return False
        
        return all(field in response_data for field in expected_fields)


class MetricsTracker:
    """Utilities for tracking test metrics and performance."""
    
    def __init__(self):
        self.start_time = None
        self.metrics = {}
    
    def start_timer(self, operation: str):
        """Start timing an operation."""
        self.start_time = time.time()
        self.metrics[operation] = {"start": self.start_time}
    
    def end_timer(self, operation: str):
        """End timing an operation."""
        if operation in self.metrics and self.start_time:
            self.metrics[operation]["end"] = time.time()
            self.metrics[operation]["duration"] = (
                self.metrics[operation]["end"] - self.metrics[operation]["start"]
            )
    
    def get_duration(self, operation: str) -> Optional[float]:
        """Get duration for an operation."""
        if operation in self.metrics and "duration" in self.metrics[operation]:
            return self.metrics[operation]["duration"]
        return None
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics."""
        summary = {
            "total_operations": len(self.metrics),
            "operations": {}
        }
        
        for operation, data in self.metrics.items():
            if "duration" in data:
                summary["operations"][operation] = {
                    "duration": data["duration"],
                    "duration_ms": data["duration"] * 1000
                }
        
        return summary
