"""Input validation: address/tool-name patterns, PID liveness, URL checks."""

import os
import re
from urllib.parse import urlparse

# Input validation patterns
HEX_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")
# Space-qualified address: space:HEX or space::HEX (overlay), with optional 0x.
# Ghidra memory-block (and therefore overlay-space) names are essentially
# unconstrained, so the space-name class is "anything except colon or
# whitespace" — the ':'/'::' separator is what distinguishes this from plain
# hex. Ghidra's AddressFactory accepts both ':' and '::' and is case-sensitive
# on the name (#184), so the bridge preserves case and never adds '0x' here.
SEGMENT_ADDRESS_PATTERN = re.compile(r"^[^\s:]+::?[0-9a-fA-F]+$")
# Handles the space::0xHEX / space:0xHEX form. Checked BEFORE SEGMENT_ADDRESS_PATTERN
# because the 'x' in '0x' is not in [0-9a-fA-F]. Group 1 captures the name AND the
# colon separator; group 2 captures the bare hex offset.
SEGMENT_ADDR_WITH_0X_PATTERN = re.compile(
    r"^([^\s:]+::?)0[xX]([0-9a-fA-F]+)$"
)
TOOL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
MAX_TOOL_NAME_LENGTH = 64
INVALID_TOOL_NAME_CHARS = re.compile(r"[^a-zA-Z0-9_-]+")
REPEATED_UNDERSCORES = re.compile(r"_+")


def is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    if pid <= 0:
        return False

    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # PROCESS_QUERY_LIMITED_INFORMATION is enough for a liveness probe and
        # avoids the POSIX-only os.kill(pid, 0) behavior that can hang on Windows.
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True

        error = kernel32.GetLastError()
        if error == 5:  # ERROR_ACCESS_DENIED: alive but not queryable.
            return True
        return False

    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Running but owned by another user
    except OSError as e:
        # Windows may raise WinError 87 ("The parameter is incorrect")
        # for clearly invalid PIDs instead of ProcessLookupError.
        if getattr(e, "winerror", None) == 87:
            return False
        raise


def validate_server_url(url: str) -> bool:
    """Validate that a TCP server URL is both safe (local-only) and usable.

    The TCP transport (``transport.tcp_request``) feeds this URL straight into a
    stdlib ``http.client.HTTPConnection(parsed.hostname, parsed.port)`` — plain
    HTTP, no TLS, and no port inference. So a URL that passes here must match how
    it will actually be dialed; otherwise validation reports "safe" and the
    request fails (or silently dials the wrong port) at connection time:

    - scheme must be ``http`` — ``https`` would be accepted then fail (the
      transport never negotiates TLS).
    - host must be loopback (``127.0.0.1``/``localhost``/``::1``).
    - port must be explicit — a missing port silently defaults to 80 in
      ``HTTPConnection``, never the Ghidra server's actual port.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme != "http":
            return False
        if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            return False
        if parsed.port is None:
            return False
        return True
    except Exception:
        return False


def validate_hex_address(address: str) -> bool:
    """Validate that an address string looks like a valid hex address or segment:offset."""
    if not address:
        return False
    if SEGMENT_ADDR_WITH_0X_PATTERN.match(address):
        return True
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return True
    return bool(HEX_ADDRESS_PATTERN.match(address))


def sanitize_tool_name(name: str) -> str:
    """Normalize an MCP tool name for clients with strict CAPI validation."""
    sanitized = INVALID_TOOL_NAME_CHARS.sub("_", name.lower())
    sanitized = REPEATED_UNDERSCORES.sub("_", sanitized).strip("_")
    if not sanitized:
        raise ValueError(f"Tool name {name!r} is empty after sanitization")
    if len(sanitized) > MAX_TOOL_NAME_LENGTH:
        sanitized = sanitized[:MAX_TOOL_NAME_LENGTH].rstrip("_")
    if not sanitized:
        raise ValueError(f"Tool name {name!r} is empty after truncation")
    if not TOOL_NAME_PATTERN.match(sanitized):
        raise ValueError(f"Sanitized tool name {sanitized!r} is still invalid")
    return sanitized


def _allocate_tool_name(base_name: str, used_names: set[str]) -> str:
    """Return a unique MCP tool name, adding a deterministic suffix on collision."""
    if base_name not in used_names:
        used_names.add(base_name)
        return base_name

    suffix = 2
    while True:
        suffix_text = f"_{suffix}"
        trimmed_base = base_name[: MAX_TOOL_NAME_LENGTH - len(suffix_text)].rstrip("_")
        if not trimmed_base:
            raise ValueError(f"Tool name {base_name!r} is too short to suffix safely")
        candidate = f"{trimmed_base}{suffix_text}"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        suffix += 1


def validate_tool_name(name: str) -> None:
    """Fail fast if an exposed MCP tool name is not CAPI-safe."""
    if not TOOL_NAME_PATTERN.match(name) or len(name) > MAX_TOOL_NAME_LENGTH:
        raise ValueError(
            f"Invalid MCP tool name {name!r}; expected {TOOL_NAME_PATTERN.pattern} and length <= {MAX_TOOL_NAME_LENGTH}"
        )


def sanitize_address(address: str) -> str:
    """Normalize address format for Ghidra AddressFactory.

    Handles:
    - space:0xHEX  -> space:HEX   (strip 0x; AddressFactory rejects 0x after colon)
    - space::0xHEX -> space::HEX  (overlay; '::' separator and case preserved)
    - SPACE:HEX    -> SPACE:HEX   (preserve case — AddressFactory is case-sensitive; see #184)
    - 0xHEX        -> 0xhex       (lowercase)
    - HEX          -> 0xHEX       (add 0x prefix)
    """
    if not address:
        return address
    address = address.strip()

    # Step 1: handle space:0xHEX / space::0xHEX form (checked first — 'x' not in
    # [0-9a-fA-F]). Group 1 already includes the ':'/'::' separator.
    m = SEGMENT_ADDR_WITH_0X_PATTERN.match(address)
    if m:
        return f"{m.group(1)}{m.group(2)}"  # case + separator preserved (#184, overlays)

    # Step 2: valid space:HEX — pass through unchanged (#184)
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return address

    # Step 3: plain hex normalization (unchanged logic)
    if not address.startswith(("0x", "0X")):
        address = "0x" + address
    return address.lower()
