"""Find the Gemini CLI binary on the system."""

from __future__ import annotations

import os
import shutil
import sys


def find_gemini_binary(override: str | None = None) -> str:
    """Locate the gemini binary.

    Search order:
      1. Explicit override path
      2. shutil.which("gemini")
      3. Platform-specific npm global/local paths

    Raises FileNotFoundError if not found.
    """
    if override:
        if os.path.isfile(override):
            return override
        raise FileNotFoundError(f"Gemini binary not found at: {override}")

    # Try PATH first
    found = shutil.which("gemini")
    if found:
        return found

    # Platform-specific fallbacks
    candidates: list[str] = []
    home = os.path.expanduser("~")

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        candidates.extend(
            [
                os.path.join(appdata, "npm", "gemini.cmd"),
                os.path.join(appdata, "npm", "gemini"),
                os.path.join(home, ".local", "bin", "gemini"),
            ]
        )
    else:
        candidates.extend(
            [
                os.path.join(home, ".npm-global", "bin", "gemini"),
                os.path.join(home, ".local", "bin", "gemini"),
                "/usr/local/bin/gemini",
            ]
        )

    for path in candidates:
        if os.path.isfile(path):
            return path

    raise FileNotFoundError(
        "Gemini CLI binary not found. Install it with: npm install -g @google/gemini-cli"
    )
