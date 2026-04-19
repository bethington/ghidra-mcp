"""Temporary script to extract MCP tool names from prompts and fun_doc.py"""

import re, glob, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Known MCP tools from the ghidra-mcp project (from endpoints.json + bridge)
# We'll use these to validate what we find
KNOWN_TOOL_PREFIXES = [
    "analyze_",
    "apply_",
    "batch_",
    "can_rename",
    "clear_",
    "clone_",
    "compare_",
    "convert_",
    "create_",
    "decompile_",
    "delete_",
    "detect_",
    "diff_",
    "disassemble_",
    "extract_",
    "find_",
    "force_",
    "get_",
    "import_",
    "inspect_",
    "list_",
    "modify_",
    "move_",
    "open_",
    "read_",
    "rename_",
    "remove_",
    "run_",
    "save_",
    "search_",
    "set_",
    "suggest_",
    "switch_",
    "validate_",
]


def is_likely_tool(name):
    """Check if a name looks like an MCP tool name"""
    return any(name.startswith(p) for p in KNOWN_TOOL_PREFIXES)


# 1) Extract from prompt files
prompt_tools = set()
for f in glob.glob("prompts/*.md"):
    text = open(f, encoding="utf-8").read()
    # Backtick-wrapped identifiers
    for m in re.findall(r"`([a-z_][a-z0-9_]*)`", text):
        if is_likely_tool(m):
            prompt_tools.add(m)
    # Plain text tool references (word boundaries)
    for m in re.findall(r"\b([a-z_][a-z0-9_]*)\b", text):
        if is_likely_tool(m) and len(m) > 8:
            prompt_tools.add(m)

print("=" * 60)
print("1) TOOL NAMES FROM PROMPT FILES (sorted)")
print("=" * 60)
for t in sorted(prompt_tools):
    print(f"  {t}")
print(f"\nTotal unique: {len(prompt_tools)}")

# 2) Extract from fun_doc.py
fundoc_text = open("fun_doc.py", encoding="utf-8").read()

# RELEVANT_TOOLS set
rt_match = re.search(r"RELEVANT_TOOLS\s*=\s*\{([^}]+)\}", fundoc_text)
relevant_tools = set()
if rt_match:
    relevant_tools = set(re.findall(r'"([a-z_][a-z0-9_]*)"', rt_match.group(1)))

# ghidra_get/ghidra_post paths -> tool names
api_paths = set()
for m in re.findall(
    r'ghidra_(?:get|post)\s*\(\s*["\']/?([a-z_][a-z0-9_/]*)["\']', fundoc_text
):
    # Convert path to tool name (strip leading /)
    path = m.strip("/")
    if "/" not in path:
        api_paths.add(path)

# String literals that look like tool names
string_tools = set()
for m in re.findall(r'["\']([a-z_][a-z0-9_]*)["\']', fundoc_text):
    if is_likely_tool(m) and len(m) > 8:
        string_tools.add(m)

all_fundoc = relevant_tools | api_paths | string_tools

print("\n" + "=" * 60)
print("2) TOOL NAMES FROM fun_doc.py (sorted)")
print("=" * 60)
print("\n  --- RELEVANT_TOOLS set ---")
for t in sorted(relevant_tools):
    print(f"  {t}")
print(f"  ({len(relevant_tools)} tools)")

print("\n  --- ghidra_get/ghidra_post API paths ---")
for t in sorted(api_paths):
    print(f"  {t}")
print(f"  ({len(api_paths)} paths)")

print("\n  --- Other string literal tool refs ---")
other = string_tools - relevant_tools - api_paths
for t in sorted(other):
    print(f"  {t}")
print(f"  ({len(other)} additional)")

print(f"\n  Total unique in fun_doc.py: {len(all_fundoc)}")

# 3) In prompts but NOT in RELEVANT_TOOLS
print("\n" + "=" * 60)
print("3) IN PROMPTS but NOT in RELEVANT_TOOLS")
print("=" * 60)
diff = prompt_tools - relevant_tools
for t in sorted(diff):
    in_api = " (but IS in ghidra_get/post calls)" if t in api_paths else ""
    in_str = " (but IS in other string refs)" if t in string_tools else ""
    print(f"  {t}{in_api}{in_str}")
print(f"\nTotal: {len(diff)}")

# 4) In RELEVANT_TOOLS but NOT in prompts
print("\n" + "=" * 60)
print("4) IN RELEVANT_TOOLS but NOT in prompts")
print("=" * 60)
diff2 = relevant_tools - prompt_tools
for t in sorted(diff2):
    print(f"  {t}")
print(f"\nTotal: {len(diff2)}")

# 5) In ghidra_get/post but NOT in RELEVANT_TOOLS
print("\n" + "=" * 60)
print("5) API paths used but NOT in RELEVANT_TOOLS")
print("=" * 60)
diff3 = api_paths - relevant_tools
for t in sorted(diff3):
    print(f"  {t}")
print(f"\nTotal: {len(diff3)}")
