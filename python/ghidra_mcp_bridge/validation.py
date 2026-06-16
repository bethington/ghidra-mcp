"""Process liveness, URL/address validation, and MCP tool-name sanitization."""

import os
from urllib.parse import urlparse

from .config import (
    HEX_ADDRESS_PATTERN,
    INVALID_TOOL_NAME_CHARS,
    MAX_TOOL_NAME_LENGTH,
    REPEATED_UNDERSCORES,
    SEGMENT_ADDR_WITH_0X_PATTERN,
    SEGMENT_ADDRESS_PATTERN,
    TOOL_NAME_PATTERN,
)


_win_kernel32 = None  # Lazily configured kernel32 handle (Windows only).


def _win_kernel32_lib():
    """Load kernel32 once with prototypes that are correct on 64-bit Python.

    Without explicit ``restype``/``argtypes``, ctypes assumes a 32-bit ``c_int``
    return, which truncates the 64-bit ``HANDLE`` that ``OpenProcess`` returns on
    64-bit Python. A truncated handle corrupts the liveness result and gets
    passed to ``CloseHandle`` (wrong-handle close / leak). ``use_last_error``
    captures the Win32 error so ``ctypes.get_last_error()`` reads it reliably
    instead of a value ctypes may have clobbered between foreign calls.
    """
    global _win_kernel32
    if _win_kernel32 is None:
        import ctypes
        from ctypes import wintypes

        lib = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]  # Windows-only
        lib.OpenProcess.restype = wintypes.HANDLE
        lib.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        lib.CloseHandle.restype = wintypes.BOOL
        lib.CloseHandle.argtypes = (wintypes.HANDLE,)
        _win_kernel32 = lib
    return _win_kernel32


def is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    if pid <= 0:
        return False

    if os.name == "nt":
        import ctypes

        kernel32 = _win_kernel32_lib()
        # PROCESS_QUERY_LIMITED_INFORMATION is enough for a liveness probe and
        # avoids the POSIX-only os.kill(pid, 0) behavior that can hang on Windows.
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True

        error = ctypes.get_last_error()
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
    """Validate that the server URL is safe to use."""
    try:
        parsed = urlparse(url)
        return parsed.hostname in ("127.0.0.1", "localhost", "::1")
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


def sanitize_address(address: str) -> str:
    """Normalize address format for Ghidra AddressFactory.

    Handles:
    - space:0xHEX  -> space:HEX   (strip 0x; AddressFactory rejects 0x after colon)
    - SPACE:HEX    -> SPACE:HEX   (preserve case — AddressFactory is case-sensitive; see #184)
    - 0xHEX        -> 0xhex       (lowercase)
    - HEX          -> 0xHEX       (add 0x prefix)
    """
    if not address:
        return address
    address = address.strip()

    # Step 1: handle space:0xHEX form (checked first — 'x' not in [0-9a-fA-F])
    m = SEGMENT_ADDR_WITH_0X_PATTERN.match(address)
    if m:
        return f"{m.group(1)}:{m.group(2)}"  # case preserved (#184)

    # Step 2: valid space:HEX — pass through unchanged (#184)
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return address

    # Step 3: plain hex normalization (unchanged logic)
    if not address.startswith(("0x", "0X")):
        address = "0x" + address
    return address.lower()


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


def allocate_tool_name(base_name: str, used_names: set[str]) -> str:
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
            f"Invalid MCP tool name {name!r}; expected {TOOL_NAME_PATTERN.pattern} "
            f"and length <= {MAX_TOOL_NAME_LENGTH}"
        )
