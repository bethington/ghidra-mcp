# Ordinal to Function Name Mapping
# This file maps ordinal numbers to their proper function names
# Format: ordinal_number -> function_name

ORDINAL_NAME_MAP = {
    10084: "ProcessUnitCoordinatesAndPath",
    10092: "ProcessUnitMovement", 
    10123: "GetUnitPosition",
    10259: "CreateUnitStruct",
    10338: "ProcessUnitAI",
    10527: "UpdateUnitAnimation", 
    10770: "ProcessUnitCollision",
    10817: "GetUnitStats",
    # Add more mappings as you identify them
    # Format: ordinal_number: "FunctionName"
}

def get_function_name(ordinal_number):
    """Get the proper function name for an ordinal number."""
    return ORDINAL_NAME_MAP.get(ordinal_number, f"Ordinal_{ordinal_number}")

def add_mapping(ordinal_number, function_name):
    """Add a new ordinal to function name mapping."""
    ORDINAL_NAME_MAP[ordinal_number] = function_name