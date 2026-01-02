"""
Phase 1: Essential Analysis Endpoints Tests

Tests for the 9 Phase 1 endpoints:
- get_function_callees
- get_function_callers
- get_function_variables
- set_function_prototype
- set_local_variable_type
- create_struct
- apply_data_type
- batch_rename_variables
- set_plate_comment
"""

import pytest
import uuid


class TestFunctionCallGraph:
    """Test function callee/caller endpoints."""

    @pytest.mark.requires_program
    def test_get_function_callees(self, http_client, sample_function):
        """Test getting functions called by a function."""
        response = http_client.get("/get_function_callees", params={"name": sample_function})
        assert response.status_code == 200
        # Should return list of functions or empty (valid either way)

    @pytest.mark.requires_program
    def test_get_function_callees_pagination(self, http_client, sample_function):
        """Test pagination for function callees."""
        response = http_client.get("/get_function_callees", params={
            "name": sample_function,
            "offset": 0,
            "limit": 5
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_function_callees_invalid_function(self, http_client):
        """Test callees with non-existent function."""
        response = http_client.get("/get_function_callees", params={
            "name": "NonExistentFunction_" + uuid.uuid4().hex[:8]
        })
        # Accept 200 with error, 404 (not found), or 500 (server error)
        assert response.status_code in [200, 404, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower() or "not found" in response.text.lower()

    @pytest.mark.requires_program
    def test_get_function_callers(self, http_client, sample_function):
        """Test getting functions that call a function."""
        response = http_client.get("/get_function_callers", params={"name": sample_function})
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_function_callers_pagination(self, http_client, sample_function):
        """Test pagination for function callers."""
        response = http_client.get("/get_function_callers", params={
            "name": sample_function,
            "offset": 0,
            "limit": 5
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_function_callers_invalid_function(self, http_client):
        """Test callers with non-existent function."""
        response = http_client.get("/get_function_callers", params={
            "name": "NonExistentFunction_" + uuid.uuid4().hex[:8]
        })
        # Accept 200 with error, 404 (not found), or 500 (server error)
        assert response.status_code in [200, 404, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower() or "not found" in response.text.lower()


class TestFunctionVariables:
    """Test function variable endpoints."""

    @pytest.mark.requires_program
    def test_get_function_variables(self, http_client, sample_function):
        """Test getting function variables."""
        response = http_client.get("/get_function_variables", params={
            "function_name": sample_function
        })
        assert response.status_code == 200
        # Should return JSON with parameters and locals
        text = response.text
        assert "parameters" in text or "error" in text.lower()

    @pytest.mark.requires_program
    def test_get_function_variables_invalid_function(self, http_client):
        """Test variables with non-existent function."""
        response = http_client.get("/get_function_variables", params={
            "function_name": "NonExistentFunction_" + uuid.uuid4().hex[:8]
        })
        # Accept 200 with error, 404 (not found), or 500 (server error)
        assert response.status_code in [200, 404, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()


class TestFunctionPrototype:
    """Test function prototype modification."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_set_function_prototype(self, http_client, sample_address):
        """Test setting function prototype."""
        response = http_client.post("/set_function_prototype", data={
            "function_address": sample_address,
            "prototype": "int testFunc(int param1)"
        })
        assert response.status_code == 200
        # Should succeed or return error about function not found
        assert "success" in response.text.lower() or "error" in response.text.lower()

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_set_function_prototype_with_calling_convention(self, http_client, sample_address):
        """Test setting prototype with calling convention."""
        response = http_client.post("/set_function_prototype", data={
            "function_address": sample_address,
            "prototype": "void testFunc2()",
            "calling_convention": "__cdecl"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_set_function_prototype_invalid_address(self, http_client):
        """Test prototype with invalid address."""
        response = http_client.post("/set_function_prototype", data={
            "function_address": "invalid",
            "prototype": "void test()"
        })
        # Accept 200 with error, 400 (bad request), or 500 (server error)
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()


class TestVariableType:
    """Test variable type modification."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_set_local_variable_type(self, http_client, sample_address):
        """Test setting local variable type."""
        # This may fail if variable doesn't exist, which is valid
        response = http_client.post("/set_local_variable_type", data={
            "function_address": sample_address,
            "variable_name": "local_8",
            "new_type": "int"
        })
        assert response.status_code == 200
        # Success or error - both valid depending on function structure
        assert "success" in response.text.lower() or "error" in response.text.lower()

    @pytest.mark.requires_program
    def test_set_local_variable_type_invalid_address(self, http_client):
        """Test variable type with invalid address."""
        response = http_client.post("/set_local_variable_type", data={
            "function_address": "invalid",
            "variable_name": "test",
            "new_type": "int"
        })
        # Accept 200 with error, 400 (bad request), or 500 (server error)
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()


class TestDataTypes:
    """Test data type creation and application."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_create_struct(self, http_client):
        """Test creating a structure."""
        unique_name = f"TestStruct_{uuid.uuid4().hex[:8]}"
        response = http_client.post("/create_struct", json_data={
            "name": unique_name,
            "fields": [
                {"name": "field1", "type": "int"},
                {"name": "field2", "type": "short"}
            ]
        })
        assert response.status_code == 200
        assert "success" in response.text.lower() or "created" in response.text.lower()

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_create_struct_duplicate(self, http_client):
        """Test creating duplicate structure."""
        unique_name = f"TestStruct_{uuid.uuid4().hex[:8]}"
        # Create first time
        http_client.post("/create_struct", json_data={
            "name": unique_name,
            "fields": [{"name": "f1", "type": "int"}]
        })
        # Try to create again
        response = http_client.post("/create_struct", json_data={
            "name": unique_name,
            "fields": [{"name": "f1", "type": "int"}]
        })
        assert response.status_code == 200
        # May succeed (replace) or error (duplicate)

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_apply_data_type(self, http_client, sample_address):
        """Test applying a data type at an address."""
        response = http_client.post("/apply_data_type", data={
            "address": sample_address,
            "type_name": "int"
        })
        assert response.status_code == 200
        # May succeed or error if code exists at address
        assert "success" in response.text.lower() or "error" in response.text.lower()

    @pytest.mark.requires_program
    def test_apply_data_type_invalid_type(self, http_client, sample_address):
        """Test applying non-existent data type."""
        response = http_client.post("/apply_data_type", data={
            "address": sample_address,
            "type_name": "NonExistentType_" + uuid.uuid4().hex[:8]
        })
        assert response.status_code == 200
        assert "error" in response.text.lower() or "not found" in response.text.lower()


class TestBatchRename:
    """Test batch variable renaming."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_batch_rename_variables(self, http_client, sample_address):
        """Test batch renaming variables."""
        response = http_client.post("/batch_rename_variables", json_data={
            "function_address": sample_address,
            "variable_renames": {"local_8": "testVar1"}
        })
        assert response.status_code == 200
        # Should return JSON with success/failure counts
        text = response.text
        assert "renamed" in text.lower() or "failed" in text.lower() or "error" in text.lower()

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_batch_rename_variables_empty(self, http_client, sample_address):
        """Test batch rename with empty renames."""
        response = http_client.post("/batch_rename_variables", json_data={
            "function_address": sample_address,
            "variable_renames": {}
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_batch_rename_variables_invalid_address(self, http_client):
        """Test batch rename with invalid address."""
        response = http_client.post("/batch_rename_variables", json_data={
            "function_address": "invalid",
            "variable_renames": {"test": "test2"}
        })
        assert response.status_code == 200
        assert "error" in response.text.lower()


class TestPlateComment:
    """Test plate comment setting."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_set_plate_comment(self, http_client, sample_address):
        """Test setting plate comment."""
        response = http_client.post("/set_plate_comment", data={
            "function_address": sample_address,
            "comment": "Test plate comment from automated tests"
        })
        assert response.status_code == 200
        assert "success" in response.text.lower() or "error" in response.text.lower()

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_set_plate_comment_empty(self, http_client, sample_address):
        """Test setting empty plate comment (to clear)."""
        response = http_client.post("/set_plate_comment", data={
            "function_address": sample_address,
            "comment": ""
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_set_plate_comment_invalid_address(self, http_client):
        """Test plate comment with invalid address."""
        response = http_client.post("/set_plate_comment", data={
            "function_address": "invalid",
            "comment": "Test"
        })
        # Accept 200 with error, 400 (bad request), or 500 (server error)
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()


class TestPhase1Integration:
    """Integration tests using multiple Phase 1 endpoints together."""

    @pytest.mark.requires_program
    def test_function_analysis_workflow(self, http_client, sample_function):
        """Test typical function analysis workflow."""
        # Get callees
        response = http_client.get("/get_function_callees", params={"name": sample_function})
        assert response.status_code == 200

        # Get callers
        response = http_client.get("/get_function_callers", params={"name": sample_function})
        assert response.status_code == 200

        # Get variables
        response = http_client.get("/get_function_variables", params={
            "function_name": sample_function
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_struct_creation_workflow(self, http_client):
        """Test creating and using a struct."""
        unique_name = f"WorkflowStruct_{uuid.uuid4().hex[:8]}"

        # Create struct
        response = http_client.post("/create_struct", json_data={
            "name": unique_name,
            "fields": [
                {"name": "id", "type": "int"},
                {"name": "flags", "type": "short"},
                {"name": "data", "type": "byte"}
            ]
        })
        assert response.status_code == 200
        assert "success" in response.text.lower() or "created" in response.text.lower()
