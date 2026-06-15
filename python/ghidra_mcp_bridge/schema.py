"""Convert the upstream /mcp/schema into internal tool defs and dispatch handlers."""

import inspect
from typing import Any

from . import connection
from .config import STATIC_TOOL_NAMES, TYPE_MAP
from .validation import allocate_tool_name, sanitize_address, sanitize_tool_name


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

        # Preserve the existing behavior for valid dynamic names that exactly
        # overlap a static bridge tool: _register_tool_def will skip them.
        if sanitized_name in STATIC_TOOL_NAMES and sanitized_name == raw_name:
            name = sanitized_name
        else:
            name = allocate_tool_name(sanitized_name, used_names)

        normalized = dict(tool_def)
        normalized["name"] = name
        normalized["original_name"] = raw_name
        normalized["sanitized_name"] = sanitized_name
        normalized["name_collided"] = name != sanitized_name
        normalized_schema.append(normalized)

    return normalized_schema


def parse_schema(raw: dict) -> list[dict]:
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


def build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))
    is_post = http_method.upper() == "POST"
    has_schema_dry_run = "dry_run" in properties
    use_synthetic_dry_run = is_post and not has_schema_dry_run

    def is_truthy(value) -> bool:
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def handler(**kwargs):
        # Sanitize address parameters before dispatch
        for pname, pdef in properties.items():
            if (
                pdef.get("param_type") == "address"
                and pname in kwargs
                and kwargs[pname] is not None
            ):
                kwargs[pname] = sanitize_address(str(kwargs[pname]))
        # Synthetic bridge dry-run goes as a query param. Schema-declared
        # dry_run must stay in kwargs so its declared source (query/body) wins.
        dry_run = kwargs.pop("dry_run", None) if use_synthetic_dry_run else None
        # Filter out None AND empty strings. Codex's MCP client passes schema
        # default values (including "") to every call, which the Ghidra
        # handler treats as "present but empty" and fails on params that
        # require a real value (e.g. /get_function_callers rejects empty
        # name/address). minimax avoids this by only sending params the LLM
        # explicitly provided, but the bridge is schema-driven and doesn't
        # know which were defaults. Empty string is not a meaningful value
        # for any current Ghidra endpoint — safe to filter.
        filtered = {
            k: v
            for k, v in kwargs.items()
            if v is not None and not (isinstance(v, str) and v == "")
        }
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            if use_synthetic_dry_run and is_truthy(dry_run):
                str_params["dry_run"] = "true"
            return connection.dispatch_get(
                endpoint, params=str_params if str_params else None
            )
        else:
            body_data = {}
            query_params = {}
            for key, value in filtered.items():
                if properties.get(key, {}).get("source") == "query":
                    query_params[key] = str(value)
                else:
                    body_data[key] = value
            if use_synthetic_dry_run and is_truthy(dry_run):
                query_params["dry_run"] = "true"
            return connection.dispatch_post(
                endpoint,
                data=body_data,
                query_params=query_params or None,
            )

    # Build function signature with proper types and defaults
    # Params with defaults must come after params without defaults
    required_params = []
    optional_params = []
    for pname, pdef in properties.items():
        json_type = pdef.get("type", "string")
        py_type: Any = TYPE_MAP.get(json_type, str)
        default = pdef.get("default", inspect.Parameter.empty)
        if pname not in required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None

        param = inspect.Parameter(
            pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=py_type
        )
        if default is inspect.Parameter.empty:
            required_params.append(param)
        else:
            optional_params.append(param)

    sig_params = required_params + optional_params
    # Add dry_run parameter for POST (write) endpoints
    if use_synthetic_dry_run:
        sig_params.append(
            inspect.Parameter(
                "dry_run",
                inspect.Parameter.KEYWORD_ONLY,
                default=False,
                annotation=bool,
            )
        )
    handler.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        sig_params, return_annotation=str
    )
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler
