"""Stable MCP contract, independent of a running Ghidra instance."""

import json
from importlib.resources import files

from . import registry, state
from .schema import _parse_schema


def initialize() -> None:
    schema = _parse_schema(json.loads(files(__package__).joinpath("tool_catalog.json").read_text(encoding="utf-8")))
    count = registry.register_tools_from_schema(schema)
    expected = len([t for t in schema if t["name"] not in registry.STATIC_TOOL_NAMES])
    if count != expected:
        raise RuntimeError(f"Incomplete bundled tool catalog: registered {count}/{expected}")
    state._catalog_frozen = True


def signature(tool: dict) -> tuple:
    """Compare executable contracts, excluding descriptions and group labels."""
    schema = tool["input_schema"]
    props = {}
    for name, value in schema.get("properties", {}).items():
        p = {k: value[k] for k in ("type", "source", "default", "allow_empty", "param_type", "aliases") if k in value}
        props[name] = p
    return (tool.get("http_method", "GET"), sorted(schema.get("required", [])), props)


def capability_error(endpoint: str, method: str, connection: state.ConnectionSnapshot | None) -> str | None:
    if not state._catalog_frozen:
        return None
    if connection is None or connection.mode == "none":
        return "No Ghidra instance connected. Use list_instances() then connect_instance(project)."
    if connection.binding is None:
        return "Instance capabilities have not been verified; reconnect with connect_instance(project)."
    live = json.loads(connection.binding)["schema"]
    actual = next((t for t in live if t["endpoint"] == endpoint), None)
    expected = next((t for t in state._full_schema if t["endpoint"] == endpoint), None)
    if actual is None:
        return f"{endpoint} is unavailable on the selected instance/transport ({connection.connected_project})."
    if expected is None or actual.get("http_method", "GET") != method or signature(actual) != signature(expected):
        return f"Incompatible schema for {endpoint}; align the bridge and Ghidra extension versions. Request not sent."
    return None
