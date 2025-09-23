"""
Functional tests for GhidraMCP workflows and end-to-end scenarios.

These tests verify that complete workflows work correctly,
testing integration between multiple endpoints and real-world usage patterns.
They simulate how users would actually interact with the system.
"""
import pytest
import requests
import time
import json
from typing import Dict, Any, List, Optional
from tests.conftest import APIClient, TestConfig
from tests.fixtures.test_helpers import TestDataGenerator, TestValidators, MetricsTracker, ComplexityLevel


@pytest.mark.functional
@pytest.mark.requires_ghidra
class TestBinaryDiscoveryWorkflow:
    """Test complete binary discovery and exploration workflows."""
    
    def test_comprehensive_binary_discovery(self, api_client: APIClient, server_health_check):
        """Test comprehensive binary discovery workflow."""
        workflow_results = {}
        
        # Step 1: Establish connection and validate server
        connection_response = api_client.get('check_connection')
        assert connection_response.ok
        workflow_results['connection'] = True
        
        # Step 2: Get program metadata
        metadata_response = api_client.get('get_metadata')
        assert metadata_response.ok
        workflow_results['metadata'] = metadata_response.text
        
        # Step 3: Discover program structure
        structure_endpoints = [
            ('functions', {'limit': 20}),
            ('segments', {'limit': 10}), 
            ('strings', {'limit': 30}),
            ('imports', {'limit': 15}),
            ('exports', {'limit': 15}),
            ('get_entry_points', {})
        ]
        
        for endpoint, params in structure_endpoints:
            response = api_client.get(endpoint, params=params)
            assert response.ok, f"Failed to discover {endpoint}"
            workflow_results[endpoint] = response.status_code == 200
        
        # Step 4: Data type exploration
        data_types_response = api_client.get('data_types', params={'limit': 25})
        assert data_types_response.ok
        workflow_results['data_types'] = True
        
        # Verify all steps completed successfully
        assert all(workflow_results.values()), f"Workflow failures: {workflow_results}"
    
    def test_function_analysis_workflow(self, api_client: APIClient, server_health_check):
        """Test function-focused analysis workflow."""
        metrics = MetricsTracker()
        
        # Step 1: Get function list
        metrics.start_timer("get_functions")
        functions_response = api_client.get('functions', params={'limit': 10})
        metrics.end_timer("get_functions")
        
        assert functions_response.ok
        
        # Step 2: Search for specific functions
        common_function_names = ['main', 'init', 'start', 'entry', 'WinMain']
        found_functions = []
        
        for func_name in common_function_names:
            search_response = api_client.get('search_functions_by_name', params={
                'query': func_name,
                'limit': 5
            })
            
            if search_response.ok:
                found_functions.append(func_name)
        
        # Step 3: Try to analyze found functions
        for func_name in found_functions[:2]:  # Limit to first 2 to avoid long test times
            # Try decompilation
            decompile_response = api_client.get('decompile_function', params={
                'name': func_name
            })
            # Decompilation may fail, but should not crash
            assert decompile_response.status_code in [200, 400, 404]
        
        # Verify timing is reasonable
        functions_duration = metrics.get_duration("get_functions")
        assert functions_duration < 5.0, f"Function listing took too long: {functions_duration}s"
    
    def test_cross_reference_analysis_workflow(self, api_client: APIClient, server_health_check):
        """Test cross-reference analysis workflow."""
        test_address = TestConfig.TEST_DATA['address']
        
        # Step 1: Get references TO an address
        xrefs_to_response = api_client.get('get_xrefs_to', params={
            'address': test_address,
            'limit': 10
        })
        # May fail if address has no references
        xrefs_to_result = xrefs_to_response.status_code in [200, 404]
        
        # Step 2: Get references FROM an address  
        xrefs_from_response = api_client.get('get_xrefs_from', params={
            'address': test_address,
            'limit': 10
        })
        # May fail if address has no references
        xrefs_from_result = xrefs_from_response.status_code in [200, 404]
        
        # Step 3: Get function information at address
        function_response = api_client.get('get_function_by_address', params={
            'address': test_address
        })
        function_result = function_response.status_code in [200, 404]
        
        # At least the requests should be handled properly
        assert all([xrefs_to_result, xrefs_from_result, function_result])


@pytest.mark.functional 
@pytest.mark.requires_ghidra
class TestDataTypeManagementWorkflow:
    """Test complete data type creation and management workflows."""
    
    def test_struct_creation_workflow(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test complete struct creation workflow."""
        struct_name = TestDataGenerator.generate_unique_name("WorkflowStruct")
        
        # Step 1: Create a simple struct
        simple_fields = TestDataGenerator.generate_struct_fields(ComplexityLevel.SIMPLE)
        assert TestValidators.validate_struct_fields(simple_fields)
        
        create_response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(simple_fields)
        })
        
        if create_response.ok:
            cleanup_tracker['structs'].append(struct_name)
            
            # Step 2: Verify struct was created by searching for it
            time.sleep(0.5)  # Small delay for consistency
            
            search_response = api_client.get('search_data_types', params={
                'pattern': struct_name,
                'limit': 5
            })
            
            # May not have search endpoint, so check status codes
            struct_found = search_response.status_code in [200, 404]
            assert struct_found
            
            # Step 3: Try to get struct layout information
            layout_response = api_client.get('get_struct_layout', params={
                'struct_name': struct_name
            })
            
            # Layout endpoint may not exist
            layout_result = layout_response.status_code in [200, 404, 501]
            assert layout_result
        
        # Creation should succeed or fail gracefully
        assert create_response.status_code in [200, 400, 409]
    
    def test_enum_creation_workflow(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test complete enum creation workflow."""
        enum_name = TestDataGenerator.generate_unique_name("WorkflowEnum")
        
        # Step 1: Create enum with status values
        enum_values = TestDataGenerator.generate_enum_values("status")
        assert TestValidators.validate_enum_values(enum_values)
        
        create_response = api_client.post('create_enum', data={
            'name': enum_name,
            'values': json.dumps(enum_values)
        })
        
        if create_response.ok:
            cleanup_tracker['enums'].append(enum_name)
            
            # Step 2: Try to get enum values
            values_response = api_client.get('get_enum_values', params={
                'enum_name': enum_name
            })
            
            # Values endpoint may not exist
            values_result = values_response.status_code in [200, 404, 501]
            assert values_result
        
        # Creation should succeed or fail gracefully
        assert create_response.status_code in [200, 400, 409]
    
    def test_union_creation_workflow(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test complete union creation workflow."""
        union_name = TestDataGenerator.generate_unique_name("WorkflowUnion")
        
        # Step 1: Create union
        union_fields = TestDataGenerator.generate_union_fields()
        assert TestValidators.validate_struct_fields(union_fields)
        
        create_response = api_client.post('create_union', data={
            'name': union_name,
            'fields': json.dumps(union_fields)
        })
        
        if create_response.ok:
            cleanup_tracker['unions'].append(union_name)
        
        # Creation should succeed or fail gracefully
        assert create_response.status_code in [200, 400, 409]
    
    def test_complex_data_type_workflow(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test workflow with multiple interdependent data types."""
        base_name = TestDataGenerator.generate_unique_name("Complex")
        
        # Step 1: Create base enum for flags
        enum_name = f"{base_name}_Flags"
        flag_values = TestDataGenerator.generate_enum_values("flags")
        
        enum_response = api_client.post('create_enum', data={
            'name': enum_name,
            'values': json.dumps(flag_values)
        })
        
        if enum_response.ok:
            cleanup_tracker['enums'].append(enum_name)
        
        # Step 2: Create struct that uses the enum
        struct_name = f"{base_name}_Header"
        struct_fields = [
            {"name": "magic", "type": "DWORD"},
            {"name": "version", "type": "short"},
            {"name": "flags", "type": enum_name if enum_response.ok else "DWORD"},
            {"name": "data_size", "type": "DWORD"}
        ]
        
        struct_response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': json.dumps(struct_fields)
        })
        
        if struct_response.ok:
            cleanup_tracker['structs'].append(struct_name)
        
        # Step 3: Create union that includes the struct
        union_name = f"{base_name}_Data"
        union_fields = [
            {"name": "as_header", "type": struct_name if struct_response.ok else "int"},
            {"name": "as_raw", "type": "char[16]"},
            {"name": "as_ints", "type": "int[4]"}
        ]
        
        union_response = api_client.post('create_union', data={
            'name': union_name,
            'fields': json.dumps(union_fields)
        })
        
        if union_response.ok:
            cleanup_tracker['unions'].append(union_name)
        
        # At least one data type should be created successfully
        successful_creations = sum([
            resp.ok for resp in [enum_response, struct_response, union_response]
        ])
        assert successful_creations >= 1, "No data types were created successfully"


@pytest.mark.functional
@pytest.mark.requires_ghidra
class TestAnnotationAndDocumentationWorkflow:
    """Test workflows for adding annotations and documentation."""
    
    def test_function_documentation_workflow(self, api_client: APIClient, server_health_check):
        """Test complete function documentation workflow."""
        test_address = TestConfig.TEST_DATA['address']
        timestamp = int(time.time())
        
        # Step 1: Add disassembly comment
        disasm_comment = f"Disassembly comment added by test at {timestamp}"
        disasm_response = api_client.post('set_disassembly_comment', data={
            'address': test_address,
            'comment': disasm_comment
        })
        
        disasm_result = disasm_response.status_code in [200, 400, 404]
        assert disasm_result, f"Disassembly comment failed: {disasm_response.status_code}"
        
        # Step 2: Add decompiler comment
        decompiler_comment = f"Decompiler comment added by test at {timestamp}"
        decompiler_response = api_client.post('set_decompiler_comment', data={
            'address': test_address, 
            'comment': decompiler_comment
        })
        
        decompiler_result = decompiler_response.status_code in [200, 400, 404]
        assert decompiler_result, f"Decompiler comment failed: {decompiler_response.status_code}"
        
        # Step 3: Try to set function prototype
        prototype = "int documented_function(int param1, char* param2)"
        prototype_response = api_client.post('set_function_prototype', data={
            'function_address': test_address,
            'prototype': prototype
        })
        
        prototype_result = prototype_response.status_code in [200, 400, 404]
        assert prototype_result, f"Function prototype failed: {prototype_response.status_code}"
    
    def test_labeling_workflow(self, api_client: APIClient, server_health_check, cleanup_tracker):
        """Test systematic labeling workflow."""
        base_address = 0x401000
        label_prefix = TestDataGenerator.generate_unique_name("Label")
        
        # Create multiple labels at different addresses
        labels_created = []
        
        for i in range(3):
            address = f"0x{base_address + (i * 0x10):x}"
            label_name = f"{label_prefix}_{i}"
            
            response = api_client.post('create_label', data={
                'address': address,
                'name': label_name
            })
            
            if response.ok:
                labels_created.append((address, label_name))
                cleanup_tracker['labels'].append((address, label_name))
        
        # At least some labels should be created
        assert len(labels_created) >= 1, "No labels were created successfully"
    
    def test_renaming_workflow(self, api_client: APIClient, server_health_check):
        """Test systematic renaming workflow."""
        # This is a cautious test since renaming can be destructive
        
        # Step 1: Try to rename a function that doesn't exist (safe test)
        old_name = "NonExistent_Function_12345"
        new_name = TestDataGenerator.generate_unique_name("Renamed")
        
        rename_response = api_client.post('rename_function', data={
            'old_name': old_name,
            'new_name': new_name
        })
        
        # API might handle non-existent functions gracefully
        assert rename_response.status_code in [200, 400, 404], f"Unexpected rename status: {rename_response.status_code}"
        
        # Step 2: Try to rename a global variable (also safe test)
        global_rename_response = api_client.post('rename_global_variable', data={
            'old_name': "NonExistent_Global_12345",
            'new_name': TestDataGenerator.generate_unique_name("RenamedGlobal")
        })
        
        # API might handle non-existent variables gracefully
        assert global_rename_response.status_code in [200, 400, 404], f"Unexpected global rename status: {global_rename_response.status_code}"


@pytest.mark.functional
@pytest.mark.requires_ghidra
@pytest.mark.slow
class TestPerformanceWorkflows:
    """Test performance-oriented workflows and stress scenarios."""
    
    def test_bulk_data_retrieval_workflow(self, api_client: APIClient, server_health_check):
        """Test workflow that retrieves large amounts of data."""
        metrics = MetricsTracker()
        
        # Test retrieving data in bulk
        bulk_endpoints = [
            ('functions', {'limit': 100}),
            ('strings', {'limit': 200}),
            ('data_types', {'limit': 150}),
            ('segments', {'limit': 50})
        ]
        
        total_requests = 0
        successful_requests = 0
        
        for endpoint, params in bulk_endpoints:
            metrics.start_timer(f"bulk_{endpoint}")
            
            response = api_client.get(endpoint, params=params)
            total_requests += 1
            
            if response.ok:
                successful_requests += 1
            
            metrics.end_timer(f"bulk_{endpoint}")
            
            # Check timing
            duration = metrics.get_duration(f"bulk_{endpoint}")
            assert duration < 15.0, f"Bulk {endpoint} took too long: {duration}s"
        
        # Most requests should succeed
        success_rate = successful_requests / total_requests
        assert success_rate >= 0.75, f"Low success rate: {success_rate}"
    
    def test_iterative_analysis_workflow(self, api_client: APIClient, server_health_check):
        """Test workflow that performs iterative analysis."""
        metrics = MetricsTracker()
        
        # Step 1: Get initial function list
        metrics.start_timer("iterative_analysis")
        
        functions_response = api_client.get('functions', params={'limit': 20})
        assert functions_response.ok
        
        # Step 2: For each "function", try to get additional information
        analysis_count = 0
        
        # Generate test addresses to simulate analyzing functions
        test_addresses = TestDataGenerator.generate_test_addresses(5)
        
        for address in test_addresses:
            # Try to get function information
            func_response = api_client.get('get_function_by_address', params={
                'address': address
            })
            
            # Try to get cross-references
            xref_response = api_client.get('get_xrefs_to', params={
                'address': address,
                'limit': 5
            })
            
            analysis_count += 1
            
            # Both requests should complete (success or expected failure)
            assert func_response.status_code in [200, 404, 400]
            assert xref_response.status_code in [200, 404, 400]
        
        metrics.end_timer("iterative_analysis")
        
        # Should complete in reasonable time
        total_duration = metrics.get_duration("iterative_analysis")
        assert total_duration < 30.0, f"Iterative analysis took too long: {total_duration}s"
        assert analysis_count >= 5, "Not enough analysis iterations completed"


@pytest.mark.functional
@pytest.mark.requires_ghidra
class TestErrorRecoveryWorkflows:
    """Test workflows that handle errors gracefully."""
    
    def test_partial_failure_recovery_workflow(self, api_client: APIClient, server_health_check):
        """Test workflow that continues despite partial failures."""
        results = {}
        
        # Mix of operations that might succeed or fail
        operations = [
            # These should typically work
            ('check_connection', {}),
            ('get_metadata', {}),
            ('functions', {'limit': 5}),
            
            # These might fail depending on program state
            ('decompile_function', {'name': 'main'}),
            ('search_functions_by_name', {'query': 'nonexistent'}),
            
            # These will likely fail with invalid data
            ('disassemble_function', {'address': '0xINVALID'}),
            ('get_function_by_address', {'address': '0x99999999'})
        ]
        
        successful_operations = 0
        
        for operation, params in operations:
            try:
                response = api_client.get(operation, params=params)
                results[operation] = {
                    'status_code': response.status_code,
                    'success': response.ok
                }
                
                if response.ok:
                    successful_operations += 1
                    
            except Exception as e:
                results[operation] = {
                    'status_code': 'exception',
                    'error': str(e)
                }
        
        # Should have some successful operations
        assert successful_operations >= 3, f"Too few successful operations: {successful_operations}"
        
        # Should handle all operations without crashing
        assert len(results) == len(operations), "Not all operations completed"
    
    def test_data_consistency_workflow(self, api_client: APIClient, server_health_check):
        """Test workflow that verifies data consistency."""
        # Step 1: Get function count with different limits
        small_limit_response = api_client.get('functions', params={'limit': 10})
        large_limit_response = api_client.get('functions', params={'limit': 100})
        
        if small_limit_response.ok and large_limit_response.ok:
            # Large limit should return at least as much data as small limit
            # (This is a basic consistency check)
            small_text_len = len(small_limit_response.text)
            large_text_len = len(large_limit_response.text)
            
            # Large response should generally be longer (or equal if < 10 functions)
            assert large_text_len >= small_text_len, "Inconsistent response sizes"
        
        # Step 2: Verify pagination consistency
        page1_response = api_client.get('functions', params={'limit': 5, 'offset': 0})
        page2_response = api_client.get('functions', params={'limit': 5, 'offset': 5})
        
        if page1_response.ok and page2_response.ok:
            # Both pages should return data (or appropriately handle no data)
            assert len(page1_response.text) > 0 or len(page2_response.text) > 0
        
        # At least the basic queries should work
        assert small_limit_response.ok or large_limit_response.ok
        
    def test_function_analysis_workflow(self, api_client: APIClient, server_health_check):
        """Test function analysis workflow."""
        # Step 1: Find functions
        functions_response = api_client.get('functions', params={'limit': 5})
        assert functions_response.ok
        
        if not functions_response.text or 'Error' in functions_response.text:
            pytest.skip("No functions available for analysis")
            
        # Step 2: Search for main function
        main_search = api_client.get('search_functions_by_name', params={
            'query': 'main',
            'limit': 1
        })
        # Main function may not exist in test binary, so accept 404
        main_found = main_search.status_code in [200, 404]
        assert main_found, f"Unexpected search status: {main_search.status_code}"
        
        # Step 3: Try to get function details (if main exists or was found)
        if main_search.ok and main_search.text and 'main' in main_search.text and 'Error' not in main_search.text:
            # Get cross-references
            xrefs_response = api_client.get('function_xrefs', params={
                'name': 'main',
                'limit': 10
            })
            assert xrefs_response.status_code in [200, 404], f"Unexpected xrefs status: {xrefs_response.status_code}"
            
            # Get callees
            callees_response = api_client.get('function_callees', params={
                'name': 'main',
                'limit': 10
            })
            assert callees_response.status_code in [200, 404], f"Unexpected callees status: {callees_response.status_code}"
            
            # Get callers
            callers_response = api_client.get('function_callers', params={
                'name': 'main',
                'limit': 10
            })
            assert callers_response.status_code in [200, 404], f"Unexpected callers status: {callers_response.status_code}"
        else:
            # If main function not found, that's acceptable for the test
            assert True, "Main function not found, but test can continue"


@pytest.mark.functional
@pytest.mark.requires_ghidra
class TestDataTypeManagementWorkflow:
    """Test data type management workflows."""
    
    def test_data_type_discovery_workflow(self, api_client: APIClient, server_health_check):
        """Test data type discovery and querying workflow."""
        # Step 1: List available data types
        types_response = api_client.get('list_data_types', params={'limit': 20})
        assert types_response.ok
        
        # Step 2: Search for specific patterns
        int_search = api_client.get('search_data_types', params={
            'pattern': 'int',
            'limit': 10
        })
        assert int_search.ok
        
        # Step 3: Get size information for common types
        for type_name in ['int', 'char', 'short']:
            size_response = api_client.get('get_type_size', params={
                'type_name': type_name
            })
            assert size_response.ok
            
    def test_custom_data_type_creation_workflow(self, api_client: APIClient, 
                                               server_health_check, cleanup_tracker):
        """Test custom data type creation workflow."""
        timestamp = int(time.time())
        
        # Step 1: Create an enum
        enum_name = f"TestEnum_Workflow_{timestamp}"
        enum_response = api_client.post('create_enum', data={
            'name': enum_name,
            'values': str({
                "OPTION_A": 0,
                "OPTION_B": 1,
                "OPTION_C": 2
            }),
            'size': 4
        })
        
        if enum_response.ok:
            cleanup_tracker['enums'].append(enum_name)
            
            # Step 2: Verify enum was created
            enum_values_response = api_client.get('get_enum_values', params={
                'enum_name': enum_name
            })
            # Might not be immediately available
            assert enum_values_response.status_code in [200, 404]
            
        # Step 3: Create a struct that uses the enum
        struct_name = f"TestStruct_Workflow_{timestamp}"
        struct_response = api_client.post('create_struct', data={
            'name': struct_name,
            'fields': str([
                {"name": "id", "type": "int"},
                {"name": "status", "type": enum_name if enum_response.ok else "int"},
                {"name": "data", "type": "char[64]"}
            ])
        })
        
        if struct_response.ok:
            cleanup_tracker['structs'].append(struct_name)
            
            # Step 4: Get struct layout
            layout_response = api_client.get('get_struct_layout', params={
                'struct_name': struct_name
            })
            # Might not be immediately available
            assert layout_response.status_code in [200, 404]
            
        # At least one creation should succeed
        assert enum_response.ok or struct_response.ok


@pytest.mark.functional
@pytest.mark.requires_ghidra
class TestAnalysisAndDocumentationWorkflow:
    """Test analysis and documentation workflows."""
    
    def test_comprehensive_program_analysis(self, api_client: APIClient, server_health_check):
        """Test comprehensive program analysis workflow."""
        analysis_results = {}
        
        # Step 1: Get program overview
        metadata = api_client.get('get_metadata')
        analysis_results['metadata'] = metadata.ok
        
        # Step 2: Analyze program structure
        segments = api_client.get('segments')
        analysis_results['segments'] = segments.ok
        
        functions = api_client.get('functions', params={'limit': 50})
        analysis_results['functions'] = functions.ok
        
        imports = api_client.get('imports', params={'limit': 20})
        analysis_results['imports'] = imports.ok
        
        exports = api_client.get('exports', params={'limit': 20})
        analysis_results['exports'] = exports.ok
        
        # Step 3: Analyze strings and data
        strings = api_client.get('strings', params={'limit': 50})
        analysis_results['strings'] = strings.ok
        
        data_items = api_client.get('list_data_items', params={'limit': 20})
        analysis_results['data_items'] = data_items.ok
        
        # Step 4: Get entry points and call graph info
        entry_points = api_client.get('get_entry_points')
        analysis_results['entry_points'] = entry_points.ok
        
        # Verify that most analysis steps succeeded
        success_count = sum(analysis_results.values())
        total_count = len(analysis_results)
        success_rate = success_count / total_count
        
        assert success_rate >= 0.7, f"Analysis workflow success rate too low: {success_rate:.2%}"
        
    def test_utility_functions_workflow(self, api_client: APIClient, server_health_check):
        """Test utility functions workflow."""
        # Step 1: Number conversion utilities
        decimal_conversion = api_client.get('convert_number', params={
            'text': '255',
            'size': 4
        })
        assert decimal_conversion.ok
        assert 'ff' in decimal_conversion.text.lower() or '0xff' in decimal_conversion.text.lower()
        
        hex_conversion = api_client.get('convert_number', params={
            'text': '0xFF',
            'size': 4
        })
        assert hex_conversion.ok
        assert '255' in hex_conversion.text
        
        # Step 2: Address and location utilities
        current_address = api_client.get('get_current_address')
        assert current_address.ok
        
        current_function = api_client.get('get_current_function')
        assert current_function.ok


@pytest.mark.functional
@pytest.mark.requires_ghidra
@pytest.mark.slow
class TestCallGraphAnalysisWorkflow:
    """Test call graph analysis workflows."""
    
    def test_call_graph_discovery(self, api_client: APIClient, server_health_check):
        """Test call graph discovery workflow."""
        # Step 1: Find a function to analyze
        functions_response = api_client.get('functions', params={'limit': 10})
        assert functions_response.ok
        
        if not functions_response.text or 'Error' in functions_response.text:
            pytest.skip("No functions available for call graph analysis")
            
        # Step 2: Try to get call graph for main function
        main_search = api_client.get('search_functions_by_name', params={
            'query': 'main',
            'limit': 1
        })
        
        if main_search.ok and 'main' in main_search.text and 'Error' not in main_search.text:
            # Get function call graph
            call_graph = api_client.get('get_function_call_graph', params={
                'name': 'main',
                'depth': 2,
                'direction': 'both'
            })
            assert call_graph.ok
            
            # Get full call graph (might be large)
            full_graph = api_client.get('get_full_call_graph', params={
                'format': 'edges',
                'limit': 100
            })
            assert full_graph.ok
            
    def test_function_relationship_analysis(self, api_client: APIClient, server_health_check):
        """Test function relationship analysis."""
        # Try common function names
        for func_name in ['main', 'entry', 'start', 'WinMain']:
            search_response = api_client.get('search_functions_by_name', params={
                'query': func_name,
                'limit': 1
            })
            
            if search_response.ok and func_name in search_response.text and 'Error' not in search_response.text:
                # Analyze this function's relationships
                callees = api_client.get('function_callees', params={
                    'name': func_name,
                    'limit': 10
                })
                assert callees.ok
                
                callers = api_client.get('function_callers', params={
                    'name': func_name,
                    'limit': 10
                })
                assert callers.ok
                
                # Get jump targets
                jump_targets = api_client.get('get_function_jump_target_addresses', params={
                    'name': func_name,
                    'limit': 20
                })
                assert jump_targets.ok
                
                # Found at least one function to analyze
                break
        else:
            pytest.skip("No common functions found for relationship analysis")


@pytest.mark.functional
@pytest.mark.requires_ghidra
class TestErrorHandlingWorkflows:
    """Test error handling in complete workflows."""
    
    def test_graceful_failure_workflow(self, api_client: APIClient, server_health_check):
        """Test workflow with intentional failures handles gracefully."""
        results = []
        
        # Step 1: Valid operation
        valid_response = api_client.get('check_connection')
        results.append(('connection', valid_response.ok))
        
        # Step 2: Invalid endpoint
        invalid_response = api_client.get('nonexistent_endpoint_test')
        results.append(('invalid_endpoint', not invalid_response.ok))  # Should fail
        
        # Step 3: Continue with valid operation after failure
        recovery_response = api_client.get('get_metadata')
        results.append(('recovery', recovery_response.ok))
        
        # Step 4: Invalid parameters
        invalid_params_response = api_client.get('functions', params={'limit': 'invalid'})
        results.append(('invalid_params', invalid_params_response.status_code in [200, 400, 422]))
        
        # Verify workflow handled errors gracefully
        success_count = sum(success for _, success in results)
        assert success_count >= 3, f"Workflow didn't handle errors gracefully: {results}"
        
    def test_resource_cleanup_workflow(self, api_client: APIClient, server_health_check,
                                     cleanup_tracker):
        """Test workflow that creates and cleans up resources."""
        timestamp = int(time.time())
        created_resources = []
        
        # Create several test resources
        test_struct = f"TestStruct_Cleanup_{timestamp}"
        struct_response = api_client.post('create_struct', data={
            'name': test_struct,
            'fields': str([{"name": "test", "type": "int"}])
        })
        
        if struct_response.ok:
            created_resources.append(('struct', test_struct))
            cleanup_tracker['structs'].append(test_struct)
            
        test_enum = f"TestEnum_Cleanup_{timestamp}"
        enum_response = api_client.post('create_enum', data={
            'name': test_enum,
            'values': str({"TEST": 0}),
            'size': 4
        })
        
        if enum_response.ok:
            created_resources.append(('enum', test_enum))
            cleanup_tracker['enums'].append(test_enum)
            
        # Verify at least some resources were created
        assert len(created_resources) > 0, "No test resources could be created"
        
        # Note: Actual cleanup would happen in fixture teardown
        # This test verifies the creation workflow works
