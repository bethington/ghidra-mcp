"""Schema parsing — converts the upstream /mcp/schema to internal tool defs."""

from .config import STATIC_TOOL_NAMES, _ALL_STATIC_TOOL_NAMES
from .validation import sanitize_tool_name, _allocate_tool_name

# JSON type → Python type mapping
_TYPE_MAP = {
    "string": str,
    "json": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
    "any": str,
    "address": str,
}


def _normalize_tool_def_names(schema: list[dict]) -> list[dict]:
    """Normalize and de-duplicate MCP-visible names while keeping HTTP endpoints intact."""
    normalized_schema: list[dict] = []
    used_names = set(STATIC_TOOL_NAMES)

    for tool_def in schema:
        raw_name = (
            tool_def.get("original_name")
            or tool_def.get("name")
            or tool_def["endpoint"].lstrip("/")
        )
        sanitized_name = sanitize_tool_name(raw_name)

        # Collision detection uses the ACTIVE static set: when the WinDbg debugger
        # proxies are suppressed on this host, their names are free, so Ghidra's own
        # TraceRmi /debugger/* endpoints (System B) keep clean names instead of _2.
        #
        # Preserve the existing behavior for valid dynamic names that exactly
        # overlap a static bridge tool: _register_tool_def will skip them.
        if sanitized_name in _ALL_STATIC_TOOL_NAMES and sanitized_name == raw_name:
            name = sanitized_name
        else:
            name = _allocate_tool_name(sanitized_name, used_names)

        normalized = dict(tool_def)
        normalized["name"] = name
        normalized["original_name"] = raw_name
        normalized["sanitized_name"] = sanitized_name
        normalized["name_collided"] = name != sanitized_name
        normalized_schema.append(normalized)

    return normalized_schema


def _parse_schema(raw: dict) -> list[dict]:
    """Convert upstream AnnotationScanner schema to internal tool defs.

    Upstream format: {"tools": [{"path", "method", "description", "category", "params": [...]}]}
    Internal format: [{"name", "endpoint", "http_method", "description", "category", "input_schema"}]
    """
    tool_defs = []
    for tool in raw.get("tools", []):
        path = tool["path"]
        raw_name = tool.get("name") or path.lstrip("/")
        params = tool.get("params", [])

        properties = {}
        required = []
        for p in params:
            pdef: dict = {"type": p.get("type", "string")}
            if p.get("description"):
                pdef["description"] = p["description"]
            if "default" in p and p["default"] is not None:
                pdef["default"] = p["default"]
            if p.get("source"):
                pdef["source"] = p["source"]
            if p.get("param_type"):
                pdef["param_type"] = p["param_type"]
            properties[p["name"]] = pdef
            if p.get("required", False):
                required.append(p["name"])

        tool_defs.append(
            {
                "name": raw_name,
                "original_name": raw_name,
                "endpoint": path,
                "http_method": tool.get("method", "GET"),
                "description": tool.get("description", ""),
                "category": tool.get("category", "unknown"),
                "category_description": tool.get("category_description", ""),
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            }
        )

    return _normalize_tool_def_names(tool_defs)
