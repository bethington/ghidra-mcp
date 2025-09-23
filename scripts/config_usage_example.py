#!/usr/bin/env python3
"""
Example: Using GhidraMCP Scripts Configuration

This script demonstrates how to use the centralized configuration
across different scripts and scenarios.
"""

from scripts_config import (
    Config, EndpointConfig, MessageConfig, TestConfig, SampleDataConfig,
    ValidationConfig, get_server_url, get_timeout, format_success, format_error
)
import requests
import json


def demonstrate_configuration_usage():
    """Demonstrate various configuration usage patterns"""
    
    print("🔧 GhidraMCP Configuration Usage Examples")
    print("=" * 50)
    
    # 1. Server Configuration
    print("\n1. Server Configuration:")
    print(f"   Server URL: {get_server_url()}")
    print(f"   Timeout: {get_timeout()}s")
    print(f"   Max Retries: {Config.MAX_RETRIES}")
    print(f"   Retry Delay: {Config.RETRY_DELAY}s")
    
    # 2. Endpoint Configuration
    print("\n2. Endpoint Categories:")
    categories = ["core", "data_types", "functions", "memory", "modification"]
    for category in categories:
        endpoints = EndpointConfig.get_endpoints_by_category(category)
        print(f"   {category.title()}: {len(endpoints)} endpoints")
    
    print(f"   Total Endpoints: {len(EndpointConfig.get_all_endpoints())}")
    
    # 3. Message Formatting
    print("\n3. Standardized Messages:")
    print(format_success("Configuration loaded successfully"))
    print(format_error("Example error message"))
    print(MessageConfig.format_test_result(8, 10))
    
    # 4. Sample Data
    print("\n4. Sample Data Available:")
    print(f"   Sample Struct: {SampleDataConfig.SAMPLE_STRUCT['name']}")
    print(f"   Sample Enum: {SampleDataConfig.SAMPLE_ENUM['name']}")
    print(f"   Sample Union: {SampleDataConfig.SAMPLE_UNION['name']}")
    print(f"   Search Terms: {len(SampleDataConfig.SEARCH_TERMS)} terms")
    
    # 5. Validation
    print("\n5. Validation Examples:")
    test_addresses = ["0x1234", "1234ABCD", "invalid_address"]
    for addr in test_addresses:
        valid = ValidationConfig.is_valid_address(addr)
        status = MessageConfig.SUCCESS if valid else MessageConfig.ERROR
        print(f"   {status} Address '{addr}': {'Valid' if valid else 'Invalid'}")
    
    # 6. File Paths
    print("\n6. Path Configuration:")
    print(f"   Scripts Directory: {Config.SCRIPTS_DIR}")
    print(f"   Project Root: {Config.PROJECT_ROOT}")
    print(f"   Logs Directory: {Config.LOGS_DIR}")
    
    # 7. Test Configuration
    print("\n7. Test Configuration:")
    print(f"   Max Test Items: {TestConfig.max_test_items}")
    print(f"   Performance Threshold: {TestConfig.performance_threshold_ms}ms")
    print(f"   Concurrent Limit: {TestConfig.concurrent_test_limit}")


def demonstrate_api_call_with_config():
    """Demonstrate making API calls using configuration"""
    
    print(f"\n{MessageConfig.TESTING} API Call with Configuration")
    print("-" * 30)
    
    server_url = get_server_url()
    
    # Test core endpoints
    core_endpoints = EndpointConfig.CORE_ENDPOINTS[:3]  # Test first 3
    
    for method, endpoint, description in core_endpoints:
        try:
            url = server_url.rstrip('/') + endpoint
            response = requests.get(url, timeout=get_timeout())
            
            if response.ok:
                print(format_success(f"{description}: Connected"))
            else:
                print(format_error(f"{description}: HTTP {response.status_code}"))
                
        except requests.exceptions.ConnectionError:
            print(format_error(f"{description}: Connection failed"))
        except Exception as e:
            print(format_error(f"{description}: {str(e)}"))


def demonstrate_sample_data_usage():
    """Demonstrate using sample data from configuration"""
    
    print(f"\n{MessageConfig.EXAMPLES} Sample Data Usage")
    print("-" * 30)
    
    # Show sample struct
    struct = SampleDataConfig.SAMPLE_STRUCT
    print(f"Sample Structure '{struct['name']}':")
    for field in struct['fields']:
        print(f"  - {field['name']}: {field['type']}")
    
    # Show sample enum
    enum = SampleDataConfig.SAMPLE_ENUM
    print(f"\nSample Enumeration '{enum['name']}':")
    for name, value in enum['values'].items():
        print(f"  - {name} = {value}")
    
    # JSON representation for API calls
    print(f"\n{MessageConfig.INFO} JSON for API calls:")
    print("Struct fields JSON:")
    print(json.dumps(struct['fields'], indent=2))


if __name__ == "__main__":
    demonstrate_configuration_usage()
    demonstrate_api_call_with_config()
    demonstrate_sample_data_usage()
    
    print(f"\n{MessageConfig.SUCCESS} Configuration demonstration complete!")
    print("\nTo use in your scripts:")
    print("from scripts_config import Config, EndpointConfig, MessageConfig")
    print("server_url = get_server_url()")
    print("endpoints = EndpointConfig.CORE_ENDPOINTS")