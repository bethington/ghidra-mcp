"""
GhidraMCP Debugger Server — HTTP server wrapping dbgeng for live debugging.

Runs as a standalone process on port 8099 (configurable).
The MCP bridge proxies debugger tool calls to this server.

Usage:
    python -m debugger.server                 # Default port 8099
    python -m debugger.server --port 8100     # Custom port
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .engine import DebugEngine
from .address_map import AddressMapper
from .protocol import (
    BreakpointType, DebuggerState, StatusResponse, WatchAccess,
)
from .d2.conventions import (
    read_args, read_return_address, parse_convention_from_prototype,
    classify_value, analyze_arg_observations,
)
from .tracing import TraceSession

logger = logging.getLogger(__name__)

# Default exports directory relative to project root
_PROJECT_ROOT = Path(__file__).parent.parent
_EXPORTS_DIR = _PROJECT_ROOT / "dll_exports"


class DebuggerServer:
    """Manages the debugger engine, address mapper, and trace session."""

    def __init__(self, exports_dir: Optional[Path] = None):
        self.engine = DebugEngine()
        self.mapper = AddressMapper()
        self.tracer: Optional[TraceSession] = None

        # Load ordinal exports
        edir = exports_dir or _EXPORTS_DIR
        if edir.is_dir():
            summary = self.mapper.load_ordinal_exports(edir)
            logger.info(f"Loaded ordinal exports: {summary}")
        else:
            logger.warning(f"Exports directory not found: {edir}")

    def _ensure_tracer(self) -> TraceSession:
        if self.tracer is None:
            self.tracer = TraceSession(self.engine, self.mapper)
        return self.tracer


class RequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the debugger server."""

    server: DebuggerHTTPServer  # type hint for the server reference

    def log_message(self, format, *args):
        logger.debug(format, *args)

    # -- Routing -----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        routes = {
            "/debugger/status": self._handle_status,
            "/debugger/modules": self._handle_modules,
            "/debugger/registers": self._handle_registers,
            "/debugger/memory": lambda: self._handle_memory(query),
            "/debugger/stack": lambda: self._handle_stack(query),
            "/debugger/breakpoints": self._handle_list_breakpoints,
            "/debugger/ordinal": lambda: self._handle_resolve_ordinal(query),
            "/debugger/address_map": self._handle_address_map,
            "/debugger/trace/log": lambda: self._handle_trace_log(query),
            "/debugger/trace/list": self._handle_trace_list,
            "/debugger/watch/log": lambda: self._handle_watch_log(query),
            "/debugger/read_args": lambda: self._handle_read_args(query),
        }

        handler = routes.get(path)
        if handler:
            self._safe_handle(handler)
        else:
            self._send_error(404, f"Unknown endpoint: {path}")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        body = self._read_json_body()

        routes = {
            "/debugger/attach": lambda: self._handle_attach(body),
            "/debugger/detach": self._handle_detach,
            "/debugger/go": self._handle_go,
            "/debugger/interrupt": self._handle_interrupt,
            "/debugger/step_into": lambda: self._handle_step_into(body),
            "/debugger/step_over": lambda: self._handle_step_over(body),
            "/debugger/breakpoint": lambda: self._handle_set_breakpoint(body),
            "/debugger/sync_modules": lambda: self._handle_sync_modules(body),
            "/debugger/trace/start": lambda: self._handle_trace_start(body),
            "/debugger/trace/stop": lambda: self._handle_trace_stop(body),
            "/debugger/watch/start": lambda: self._handle_watch_start(body),
            "/debugger/watch/stop": lambda: self._handle_watch_stop(body),
        }

        handler = routes.get(path)
        if handler:
            self._safe_handle(handler)
        else:
            self._send_error(404, f"Unknown endpoint: {path}")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # DELETE /debugger/breakpoint/{id}
        if path.startswith("/debugger/breakpoint/"):
            bp_id_str = path.split("/")[-1]
            try:
                bp_id = int(bp_id_str)
                self._safe_handle(lambda: self._handle_remove_breakpoint(bp_id))
            except ValueError:
                self._send_error(400, f"Invalid breakpoint ID: {bp_id_str}")
        else:
            self._send_error(404, f"Unknown endpoint: {path}")

    # -- Handler implementations -------------------------------------------

    def _handle_status(self):
        ds = self._ds()
        engine = ds.engine
        status = StatusResponse(
            state=engine.get_state(),
            target_pid=engine.get_target_pid(),
            target_name=engine.get_target_name(),
            module_count=len(ds.mapper.get_all_modules()),
            breakpoint_count=len(engine.list_breakpoints()) if engine.get_state() != DebuggerState.DETACHED else 0,
            active_traces=ds.tracer.active_count() if ds.tracer else 0,
            active_watches=ds.tracer.watch_count() if ds.tracer else 0,
        )
        self._send_json(status.to_dict())

    def _handle_attach(self, body: dict):
        ds = self._ds()
        target = body.get("target", body.get("pid", ""))
        if not target:
            self._send_error(400, "Missing 'target' (process name or PID)")
            return
        result = ds.engine.attach(str(target))
        self._send_json(result)

    def _handle_detach(self):
        ds = self._ds()
        # Stop all traces first
        if ds.tracer:
            ds.tracer.stop_all()
        result = ds.engine.detach()
        self._send_json(result)

    def _handle_modules(self):
        ds = self._ds()
        modules = ds.engine.get_modules()
        # Enrich with Ghidra bases from mapper
        result = []
        for mod in modules:
            mapping = ds.mapper.get_module(mod.name)
            if mapping:
                mod.ghidra_base = mapping.ghidra_base
            result.append(mod.to_dict())
        self._send_json({"modules": result, "count": len(result)})

    def _handle_sync_modules(self, body: dict):
        ds = self._ds()
        ghidra_bases = body.get("ghidra_bases", {})
        if not ghidra_bases:
            self._send_error(400, "Missing 'ghidra_bases' dict")
            return
        # Convert hex string values to int if needed
        parsed_bases = {}
        for name, base in ghidra_bases.items():
            if isinstance(base, str):
                parsed_bases[name] = int(base, 16) if base.startswith("0x") else int(base)
            else:
                parsed_bases[name] = int(base)

        runtime_modules = ds.engine.get_modules()
        result = ds.mapper.update_from_modules(runtime_modules, parsed_bases)
        self._send_json(result)

    def _handle_address_map(self):
        ds = self._ds()
        modules = ds.mapper.get_all_modules()
        result = []
        for m in modules:
            result.append({
                "name": m.name,
                "ghidra_base": f"0x{m.ghidra_base:08X}",
                "runtime_base": f"0x{m.runtime_base:08X}",
                "size": f"0x{m.size:X}",
                "offset": f"0x{m.offset:+X}",
            })
        self._send_json({"mappings": result, "count": len(result)})

    def _handle_registers(self):
        ds = self._ds()
        regs = ds.engine.get_registers()
        formatted = {k: f"0x{v:08X}" for k, v in regs.items()}
        self._send_json({"registers": formatted})

    def _handle_memory(self, query: dict):
        ds = self._ds()
        addr_str = query.get("address", "")
        size = int(query.get("size", "64"))
        addr_type = query.get("address_type", "runtime")

        if not addr_str:
            self._send_error(400, "Missing 'address' parameter")
            return

        address = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

        # Translate if Ghidra address
        if addr_type == "ghidra":
            module = query.get("module", "")
            address = ds.mapper.to_runtime(address, module or None)

        data = ds.engine.read_memory(address, min(size, 4096))

        # Format as hex dump + dword interpretation
        hex_str = data.hex()
        dwords = []
        for i in range(0, len(data) - 3, 4):
            val = int.from_bytes(data[i:i+4], "little")
            dwords.append(f"0x{val:08X}")

        self._send_json({
            "address": f"0x{address:08X}",
            "size": len(data),
            "hex": hex_str,
            "dwords": dwords,
        })

    def _handle_stack(self, query: dict):
        ds = self._ds()
        depth = int(query.get("depth", "20"))
        frames = ds.engine.get_stack_trace(depth)

        # Enrich with Ghidra addresses
        for frame in frames:
            addr_str = frame.get("instruction_offset", "")
            if addr_str:
                addr = int(addr_str, 16)
                mapped = ds.mapper.try_to_ghidra(addr)
                if mapped:
                    frame["ghidra_module"] = mapped[0]
                    frame["ghidra_address"] = f"0x{mapped[1]:08X}"

        self._send_json({"frames": frames, "depth": len(frames)})

    def _handle_read_args(self, query: dict):
        ds = self._ds()
        convention = query.get("convention", "__stdcall")
        count = int(query.get("count", "4"))
        arg_names = query.get("arg_names", "")

        regs = ds.engine.get_registers()
        args = read_args(regs, ds.engine.read_dword, convention, count)

        names = [n.strip() for n in arg_names.split(",")] if arg_names else []
        result_args = []
        for i, val in enumerate(args):
            entry: dict = {"index": i, "value": f"0x{val:08X}"}
            if i < len(names) and names[i]:
                entry["name"] = names[i]
            entry["classification"] = classify_value(val)
            result_args.append(entry)

        self._send_json({
            "convention": convention,
            "args": result_args,
            "return_address": f"0x{read_return_address(regs, ds.engine.read_dword):08X}",
        })

    def _handle_go(self):
        ds = self._ds()
        result = ds.engine.go_nowait()
        self._send_json(result)

    def _handle_interrupt(self):
        ds = self._ds()
        result = ds.engine.interrupt()
        self._send_json(result)

    def _handle_step_into(self, body: dict):
        ds = self._ds()
        count = int(body.get("count", 1))
        result = ds.engine.step_into(count)
        self._send_json(result)

    def _handle_step_over(self, body: dict):
        ds = self._ds()
        count = int(body.get("count", 1))
        result = ds.engine.step_over(count)
        self._send_json(result)

    def _handle_set_breakpoint(self, body: dict):
        ds = self._ds()
        ghidra_addr_str = body.get("ghidra_address", "")
        runtime_addr_str = body.get("runtime_address", "")
        module = body.get("module", "")
        bp_type_str = body.get("type", "software")
        oneshot = body.get("oneshot", False)

        # Resolve address
        if ghidra_addr_str:
            ghidra_addr = int(ghidra_addr_str, 16) if isinstance(ghidra_addr_str, str) else int(ghidra_addr_str)
            runtime_addr = ds.mapper.to_runtime(ghidra_addr, module or None)
        elif runtime_addr_str:
            runtime_addr = int(runtime_addr_str, 16) if isinstance(runtime_addr_str, str) else int(runtime_addr_str)
            ghidra_addr = None
            mapped = ds.mapper.try_to_ghidra(runtime_addr)
            if mapped:
                ghidra_addr = mapped[1]
        else:
            self._send_error(400, "Missing 'ghidra_address' or 'runtime_address'")
            return

        bp_type = BreakpointType.HARDWARE if bp_type_str == "hardware" else BreakpointType.SOFTWARE
        bp_id = ds.engine.set_breakpoint(runtime_addr, bp_type, oneshot)

        self._send_json({
            "id": bp_id,
            "runtime_address": f"0x{runtime_addr:08X}",
            "ghidra_address": f"0x{ghidra_addr:08X}" if ghidra_addr else None,
            "module": module,
            "type": bp_type.value,
            "oneshot": oneshot,
        })

    def _handle_remove_breakpoint(self, bp_id: int):
        ds = self._ds()
        ds.engine.remove_breakpoint(bp_id)
        self._send_json({"removed": bp_id})

    def _handle_list_breakpoints(self):
        ds = self._ds()
        bps = ds.engine.list_breakpoints()

        # Enrich with Ghidra addresses
        for bp in bps:
            addr_str = bp.get("address", "")
            if addr_str:
                addr = int(addr_str, 16)
                mapped = ds.mapper.try_to_ghidra(addr)
                if mapped:
                    bp["ghidra_module"] = mapped[0]
                    bp["ghidra_address"] = f"0x{mapped[1]:08X}"

        self._send_json({"breakpoints": bps, "count": len(bps)})

    def _handle_resolve_ordinal(self, query: dict):
        ds = self._ds()
        dll = query.get("dll", "")
        ordinal_str = query.get("ordinal", "")
        if not dll or not ordinal_str:
            self._send_error(400, "Missing 'dll' and/or 'ordinal' parameter")
            return
        ordinal = int(ordinal_str)
        result = ds.mapper.resolve_ordinal(dll, ordinal)
        if result is None:
            self._send_error(404, f"Ordinal {ordinal} not found in {dll}")
        else:
            self._send_json(result)

    # -- Tracing endpoints -------------------------------------------------

    def _handle_trace_start(self, body: dict):
        ds = self._ds()
        tracer = ds._ensure_tracer()

        ghidra_addr_str = body.get("ghidra_address", "")
        module = body.get("module", "")
        convention = body.get("convention", "__stdcall")
        arg_count = int(body.get("arg_count", 4))
        arg_names_str = body.get("arg_names", "")
        capture_return = body.get("capture_return", False)
        max_hits = int(body.get("max_hits", 0))

        if not ghidra_addr_str:
            self._send_error(400, "Missing 'ghidra_address'")
            return

        ghidra_addr = int(ghidra_addr_str, 16) if isinstance(ghidra_addr_str, str) else int(ghidra_addr_str)
        arg_names = [n.strip() for n in arg_names_str.split(",") if n.strip()] if arg_names_str else None

        trace_id = tracer.add_function_trace(
            ghidra_address=ghidra_addr,
            module=module,
            convention=convention,
            arg_count=arg_count,
            arg_names=arg_names,
            capture_return=capture_return,
            max_hits=max_hits,
        )
        self._send_json({"trace_id": trace_id, "status": "started"})

    def _handle_trace_stop(self, body: dict):
        ds = self._ds()
        if ds.tracer is None:
            self._send_json({"stopped": 0})
            return
        trace_id = body.get("trace_id", -1)
        if trace_id == -1:
            count = ds.tracer.stop_all()
            self._send_json({"stopped": count})
        else:
            ds.tracer.stop_trace(int(trace_id))
            self._send_json({"stopped": 1, "trace_id": trace_id})

    def _handle_trace_log(self, query: dict):
        ds = self._ds()
        if ds.tracer is None:
            self._send_json({"entries": [], "count": 0})
            return
        trace_id = int(query.get("trace_id", -1))
        last_n = int(query.get("last_n", 50))
        entries = ds.tracer.get_log(trace_id, last_n)
        self._send_json({
            "entries": [e.to_dict() for e in entries],
            "count": len(entries),
        })

    def _handle_trace_list(self):
        ds = self._ds()
        if ds.tracer is None:
            self._send_json({"traces": [], "count": 0})
            return
        traces = ds.tracer.list_traces()
        self._send_json({
            "traces": [t.to_dict() for t in traces],
            "count": len(traces),
        })

    # -- Watch endpoints ---------------------------------------------------

    def _handle_watch_start(self, body: dict):
        ds = self._ds()
        tracer = ds._ensure_tracer()

        ghidra_addr_str = body.get("ghidra_address", "")
        module = body.get("module", "")
        size = int(body.get("size", 4))
        access = body.get("access", "write")

        if not ghidra_addr_str:
            self._send_error(400, "Missing 'ghidra_address'")
            return

        ghidra_addr = int(ghidra_addr_str, 16) if isinstance(ghidra_addr_str, str) else int(ghidra_addr_str)

        watch_id = tracer.add_data_watch(
            ghidra_address=ghidra_addr,
            module=module,
            size=size,
            access=access,
        )
        self._send_json({"watch_id": watch_id, "status": "started"})

    def _handle_watch_stop(self, body: dict):
        ds = self._ds()
        if ds.tracer is None:
            self._send_json({"stopped": 0})
            return
        watch_id = body.get("watch_id", -1)
        if watch_id == -1:
            count = ds.tracer.stop_all_watches()
            self._send_json({"stopped": count})
        else:
            ds.tracer.stop_watch(int(watch_id))
            self._send_json({"stopped": 1, "watch_id": watch_id})

    def _handle_watch_log(self, query: dict):
        ds = self._ds()
        if ds.tracer is None:
            self._send_json({"entries": [], "count": 0})
            return
        watch_id = int(query.get("watch_id", -1))
        last_n = int(query.get("last_n", 50))
        entries = ds.tracer.get_watch_log(watch_id, last_n)
        self._send_json({
            "entries": [e.to_dict() for e in entries],
            "count": len(entries),
        })

    # -- Utilities ---------------------------------------------------------

    def _ds(self) -> DebuggerServer:
        return self.server.debugger_server

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str):
        self._send_json({"error": message}, status)

    def _safe_handle(self, handler):
        try:
            handler()
        except Exception as e:
            logger.error(f"Error handling request: {traceback.format_exc()}")
            self._send_error(500, str(e))


class DebuggerHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server with reference to the DebuggerServer."""
    daemon_threads = True

    def __init__(self, address, handler_class, debugger_server: DebuggerServer):
        self.debugger_server = debugger_server
        super().__init__(address, handler_class)


def main():
    parser = argparse.ArgumentParser(description="GhidraMCP Debugger Server")
    parser.add_argument("--port", type=int, default=8099,
                        help="HTTP server port (default: 8099)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--exports-dir", type=str, default=None,
                        help="Path to dll_exports/ directory")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    exports_dir = Path(args.exports_dir) if args.exports_dir else None
    ds = DebuggerServer(exports_dir)

    server = DebuggerHTTPServer(
        (args.host, args.port), RequestHandler, ds)

    logger.info(f"Debugger server starting on {args.host}:{args.port}")

    def shutdown_handler(sig, frame):
        logger.info("Shutting down...")
        if ds.engine.get_state() != DebuggerState.DETACHED:
            try:
                ds.engine.detach()
            except Exception:
                pass
        server.shutdown()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("Server stopped")


if __name__ == "__main__":
    main()
