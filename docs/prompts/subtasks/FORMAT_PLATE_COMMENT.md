# FORMAT_PLATE_COMMENT (Haiku Subtask)

Format analysis results into a structured plate comment.
This is a template-filling task - no semantic analysis required.

## Input

JSON with function analysis results:

```json
{
  "function_name": "ProcessPlayerSlots",
  "summary": "Iterates player inventory slots and validates each item",
  "classification": "Worker",
  "calling_convention": "__fastcall",
  "algorithm_steps": [
    "Get inventory pointer from player unit",
    "Loop through slots 0 to max_slots",
    "For each slot, check if item exists",
    "Validate item state flags",
    "Return count of valid items"
  ],
  "parameters": [
    {"name": "pUnit", "type": "UnitAny *", "desc": "Player unit pointer", "implicit": false},
    {"name": "dwFlags", "type": "uint", "desc": "Validation flags", "implicit": false}
  ],
  "returns": {
    "type": "int",
    "success": "Count of valid items",
    "error": "-1 on NULL inventory"
  },
  "special_cases": [
    "Returns 0 if inventory is empty",
    "Skips slots with NULL item pointers"
  ],
  "magic_numbers": [
    {"value": "0x24", "meaning": "Slot structure stride (36 bytes)"},
    {"value": "0x80", "meaning": "Item validated flag"}
  ],
  "memory_model": {
    "allocates": false,
    "ownership": "Does not take ownership of pUnit",
    "globals": ["g_dwMaxSlots"]
  }
}
```

## Output Template

Generate plain text (no markdown) following this structure:

```
[One-line summary]

Algorithm:
1. [Step 1]
2. [Step 2]
...

Parameters:
  [name] ([type]) - [description]
  [name] ([type]) - [description] [IMPLICIT if true]

Returns:
  [type] - [success description]
  Error: [error description]

[OPTIONAL SECTIONS - include only if data provided]

Special Cases:
  - [case 1]
  - [case 2]

Magic Numbers:
  [value] - [meaning]

Memory:
  [ownership/allocation notes]
```

## Formatting Rules

1. **No decorative borders** - plain text only
2. **Algorithm steps** - numbered, start with verb
3. **Parameters** - one per line, type in parentheses
4. **IMPLICIT** - append to parameters not in prototype
5. **Special Cases** - bullet list with dash
6. **Magic Numbers** - hex format, aligned
7. **Omit empty sections** - don't include if no data

## Example Output

```
Iterates player inventory slots and validates each item

Algorithm:
1. Get inventory pointer from player unit
2. Loop through slots 0 to max_slots
3. For each slot, check if item exists
4. Validate item state flags
5. Return count of valid items

Parameters:
  pUnit (UnitAny *) - Player unit pointer
  dwFlags (uint) - Validation flags

Returns:
  int - Count of valid items
  Error: -1 on NULL inventory

Special Cases:
  - Returns 0 if inventory is empty
  - Skips slots with NULL item pointers

Magic Numbers:
  0x24 - Slot structure stride (36 bytes)
  0x80 - Item validated flag

Memory:
  Does not take ownership of pUnit
  Accesses global: g_dwMaxSlots
```

## Rules

1. Output ONLY the formatted comment text
2. No JSON wrapper in output
3. No markdown formatting
4. Include only sections that have data
5. Keep descriptions concise
6. Use consistent indentation (2 spaces)
