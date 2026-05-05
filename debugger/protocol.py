"""Shared data types for debugger server <-> bridge communication."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


def _hex_addr(value: int) -> str:
    width = 16 if value > 0xFFFFFFFF else 8
    return f"0x{value:0{width}X}"


class DebuggerState(str, Enum):
    DETACHED = "detached"
    ATTACHED = "attached"
    RUNNING = "running"
    STOPPED = "stopped"
    EXITED = "exited"


class BreakpointType(str, Enum):
    SOFTWARE = "software"
    HARDWARE = "hardware"


class WatchAccess(str, Enum):
    READ = "read"
    WRITE = "write"
    READ_WRITE = "readwrite"


@dataclass
class ModuleInfo:
    name: str
    runtime_base: int
    size: int
    ghidra_base: Optional[int] = None
    image_path: Optional[str] = None
    loaded_name: Optional[str] = None
    ghidra_name: Optional[str] = None
    match_kind: Optional[str] = None
    match_key: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "runtime_base": _hex_addr(self.runtime_base),
            "size": f"0x{self.size:X}",
        }
        if self.image_path:
            d["image_path"] = self.image_path
        if self.loaded_name:
            d["loaded_name"] = self.loaded_name
        if self.ghidra_base is not None:
            d["ghidra_base"] = _hex_addr(self.ghidra_base)
            d["offset"] = f"0x{self.runtime_base - self.ghidra_base:+X}"
        if self.ghidra_name:
            d["ghidra_name"] = self.ghidra_name
        if self.match_kind:
            d["match_kind"] = self.match_kind
        if self.match_key:
            d["match_key"] = self.match_key
        return d


@dataclass
class BreakpointInfo:
    bp_id: int
    runtime_address: int
    ghidra_address: Optional[int] = None
    module: Optional[str] = None
    bp_type: BreakpointType = BreakpointType.SOFTWARE
    enabled: bool = True
    oneshot: bool = False
    hit_count: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.bp_id,
            "runtime_address": _hex_addr(self.runtime_address),
            "ghidra_address": _hex_addr(self.ghidra_address) if self.ghidra_address is not None else None,
            "module": self.module,
            "type": self.bp_type.value,
            "enabled": self.enabled,
            "oneshot": self.oneshot,
            "hit_count": self.hit_count,
        }


@dataclass
class TraceEntry:
    timestamp: float
    trace_id: int
    ghidra_address: Optional[int]
    module: str
    args: list[int]
    arg_names: Optional[list[str]] = None
    return_value: Optional[int] = None
    caller: Optional[int] = None
    caller_ghidra: Optional[int] = None
    caller_symbol: Optional[str] = None
    thread_id: Optional[int] = None

    def to_dict(self) -> dict:
        d: dict = {
            "timestamp": round(self.timestamp, 4),
            "trace_id": self.trace_id,
            "ghidra_address": _hex_addr(self.ghidra_address) if self.ghidra_address is not None else None,
            "module": self.module,
        }
        if self.arg_names and len(self.arg_names) == len(self.args):
            d["args"] = {
                name: _hex_addr(val) for name, val in zip(self.arg_names, self.args)
            }
        else:
            d["args"] = [_hex_addr(v) for v in self.args]
        if self.return_value is not None:
            d["return_value"] = _hex_addr(self.return_value)
        if self.caller is not None:
            d["caller"] = _hex_addr(self.caller)
        if self.caller_ghidra is not None:
            d["caller_ghidra"] = _hex_addr(self.caller_ghidra)
        if self.caller_symbol:
            d["caller_symbol"] = self.caller_symbol
        if self.thread_id is not None:
            d["thread_id"] = self.thread_id
        return d


@dataclass
class TracePointInfo:
    trace_id: int
    ghidra_address: Optional[int]
    module: str
    convention: str
    arg_count: int
    arg_names: Optional[list[str]]
    capture_return: bool
    max_hits: int
    hit_count: int = 0
    active: bool = True

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "ghidra_address": _hex_addr(self.ghidra_address) if self.ghidra_address is not None else None,
            "module": self.module,
            "convention": self.convention,
            "arg_count": self.arg_count,
            "arg_names": self.arg_names,
            "capture_return": self.capture_return,
            "max_hits": self.max_hits,
            "hit_count": self.hit_count,
            "active": self.active,
        }


@dataclass
class WatchHit:
    timestamp: float
    watch_id: int
    address: int
    ghidra_address: Optional[int]
    size: int
    access: str
    value: Optional[int] = None
    accessor_address: Optional[int] = None
    accessor_ghidra: Optional[int] = None
    accessor_symbol: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {
            "timestamp": round(self.timestamp, 4),
            "watch_id": self.watch_id,
            "address": _hex_addr(self.address),
            "size": self.size,
            "access": self.access,
        }
        if self.ghidra_address is not None:
            d["ghidra_address"] = _hex_addr(self.ghidra_address)
        if self.value is not None:
            d["value"] = _hex_addr(self.value)
        if self.accessor_address is not None:
            d["accessor"] = _hex_addr(self.accessor_address)
        if self.accessor_ghidra is not None:
            d["accessor_ghidra"] = _hex_addr(self.accessor_ghidra)
        if self.accessor_symbol:
            d["accessor_symbol"] = self.accessor_symbol
        return d


@dataclass
class StatusResponse:
    state: DebuggerState
    target_pid: Optional[int] = None
    target_name: Optional[str] = None
    module_count: int = 0
    breakpoint_count: int = 0
    active_traces: int = 0
    active_watches: int = 0

    def to_dict(self) -> dict:
        d: dict = {"state": self.state.value}
        if self.target_pid is not None:
            d["target_pid"] = self.target_pid
        if self.target_name:
            d["target_name"] = self.target_name
        d["module_count"] = self.module_count
        d["breakpoint_count"] = self.breakpoint_count
        d["active_traces"] = self.active_traces
        d["active_watches"] = self.active_watches
        return d
