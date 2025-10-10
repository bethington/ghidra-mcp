#!/bin/bash
# Test script for v1.5.0 new endpoints
# Run this after starting the Ghidra MCP server

SERVER="http://127.0.0.1:8089"

echo "Testing GhidraMCP v1.5.0 New Endpoints"
echo "======================================"
echo ""

# Check server is running
echo "1. Testing server connection..."
RESPONSE=$(curl -s "$SERVER/check_connection" 2>/dev/null)
if [ -z "$RESPONSE" ]; then
    echo "❌ FAILED: Server not responding"
    echo ""
    echo "Please ensure:"
    echo "  1. Ghidra is running"
    echo "  2. A program/binary is loaded in CodeBrowser"
    echo "  3. MCP server is started (Tools > GhidraMCP > Start MCP Server)"
    exit 1
else
    echo "✅ PASSED: $RESPONSE"
fi
echo ""

# Test each new v1.5.0 endpoint
echo "2. Testing get_valid_data_types..."
RESPONSE=$(curl -s "$SERVER/get_valid_data_types" 2>/dev/null)
if echo "$RESPONSE" | grep -q "builtin_types"; then
    echo "✅ PASSED: get_valid_data_types"
else
    echo "❌ FAILED: get_valid_data_types"
    echo "   Response: $RESPONSE"
fi
echo ""

echo "3. Testing batch_set_comments (requires function address)..."
RESPONSE=$(curl -s -X POST "$SERVER/batch_set_comments" \
    -H "Content-Type: application/json" \
    -d '{"function_address":"0x401000","plate_comment":"Test comment"}' 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(success|error)"; then
    echo "✅ PASSED: batch_set_comments endpoint exists"
    echo "   Response: $RESPONSE"
else
    echo "❌ FAILED: batch_set_comments endpoint not found"
fi
echo ""

echo "4. Testing set_plate_comment (requires function address)..."
RESPONSE=$(curl -s -X POST "$SERVER/set_plate_comment" \
    -d "function_address=0x401000&comment=Test" 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(success|error)"; then
    echo "✅ PASSED: set_plate_comment endpoint exists"
    echo "   Response: $RESPONSE"
else
    echo "❌ FAILED: set_plate_comment endpoint not found"
fi
echo ""

echo "5. Testing get_function_variables (requires function name)..."
RESPONSE=$(curl -s "$SERVER/get_function_variables?function_name=main" 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(parameters|error|function_name)"; then
    echo "✅ PASSED: get_function_variables endpoint exists"
else
    echo "❌ FAILED: get_function_variables endpoint not found"
fi
echo ""

echo "6. Testing batch_rename_function_components (requires parameters)..."
RESPONSE=$(curl -s -X POST "$SERVER/batch_rename_function_components" \
    -H "Content-Type: application/json" \
    -d '{"old_function_name":"test","new_function_name":"test2"}' 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(success|error)"; then
    echo "✅ PASSED: batch_rename_function_components endpoint exists"
else
    echo "❌ FAILED: batch_rename_function_components endpoint not found"
fi
echo ""

echo "7. Testing analyze_function_completeness (requires function name)..."
RESPONSE=$(curl -s "$SERVER/analyze_function_completeness?function_name=main" 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(completeness_score|error|function_name)"; then
    echo "✅ PASSED: analyze_function_completeness endpoint exists"
else
    echo "❌ FAILED: analyze_function_completeness endpoint not found"
fi
echo ""

echo "8. Testing validate_data_type (requires parameters)..."
RESPONSE=$(curl -s "$SERVER/validate_data_type?address=0x401000&type_name=int" 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(can_apply|error)"; then
    echo "✅ PASSED: validate_data_type endpoint exists"
else
    echo "❌ FAILED: validate_data_type endpoint not found"
fi
echo ""

echo "9. Testing suggest_data_type (requires address)..."
RESPONSE=$(curl -s "$SERVER/suggest_data_type?address=0x401000" 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(suggested_types|error)"; then
    echo "✅ PASSED: suggest_data_type endpoint exists"
else
    echo "❌ FAILED: suggest_data_type endpoint not found"
fi
echo ""

echo "10. Testing batch_apply_data_types (requires JSON payload)..."
RESPONSE=$(curl -s -X POST "$SERVER/batch_apply_data_types" \
    -H "Content-Type: application/json" \
    -d '{"type_applications":[{"address":"0x401000","type_name":"int"}]}' 2>/dev/null)
if echo "$RESPONSE" | grep -q -E "(success|error)"; then
    echo "✅ PASSED: batch_apply_data_types endpoint exists"
else
    echo "❌ FAILED: batch_apply_data_types endpoint not found"
fi
echo ""

echo "======================================"
echo "Testing Complete"
echo ""
echo "Note: Some tests may show errors if:"
echo "  - No program is loaded in Ghidra"
echo "  - Specified addresses/functions don't exist"
echo "  - This is expected - we're just verifying endpoints exist"
