"""Desktop notification channel for states that need a human.

Why this exists (2026-07-30): every degradation the dashboard detects was
reported to exactly one place -- a log file inside a hidden, elevated window.
The oracle went down at ~21:04, all six prove workers drained into
`oracle_unavailable` skips and exited, and the whole fleet sat idle for 70
minutes with nothing to say so. `ce0c6ae1` burned 50 of 52 candidates on a
dead oracle. A banner in a browser tab nobody has focused is the same failure
with extra steps.

Design constraints, learned from the surrounding code:

* **No new dependencies.** fun-doc already refuses to add psutil for a
  process check (see oracle_health.is_game_running); a toast is not worth a
  wheel either. This shells out to the Windows PowerShell already on the box.
* **Never block the caller.** Notifications fire from the oracle poll thread
  and the Ghidra health thread. A wedged PowerShell must not wedge a monitor,
  so every send is detached and best-effort.
* **Never raise.** A notifier that can throw turns a recoverable outage into
  a crashed monitor thread. Every entry point swallows.
* **Edge-triggered, not level-triggered.** `notify_transition` fires only when
  a subsystem CHANGES state. Re-toasting every 45s poll would train you to
  dismiss them on sight, which is exactly as useless as not sending them.

Two delivery paths, tried in order:

1. WinRT toast (`Windows.UI.Notifications`) under the built-in Windows
   PowerShell AppID. Unregistered AppIDs are silently dropped by the shell,
   so we deliberately borrow PowerShell's own -- it is registered on every
   Windows install.
2. `NotifyIcon.ShowBalloonTip` fallback for hosts where the WinRT projection
   is unavailable (PowerShell 7 without the compat layer, stripped SKUs).

Set ``FUNDOC_NOTIFY=0`` to silence the channel entirely; the banner and the
logs are unaffected.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

# Master switch. Off => every send is a no-op that still returns cleanly, so
# callers never need to branch on it.
NOTIFY_ENABLED = os.environ.get("FUNDOC_NOTIFY", "1") == "1"

# Windows PowerShell's own registered AppID. A toast sent under an
# UNREGISTERED AppID is dropped by the shell without an error -- the send
# "succeeds" and nothing appears, which is the worst possible failure mode for
# an alerting path. Borrowing a guaranteed-registered one is the documented
# workaround for scripts that have no Start Menu presence of their own.
_POWERSHELL_APP_ID = (
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
)

# Absolute path so an exotic PATH can't shadow it, with a bare-name fallback.
_PS = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
)
if not os.path.exists(_PS):  # pragma: no cover - environment dependent
    _PS = "powershell.exe"

# Rate limit per (subsystem, state) so a flapping dependency cannot spam the
# action center. 5 minutes is well under any real outage and well over the
# 45s oracle poll.
_MIN_REPEAT_SEC = float(os.environ.get("FUNDOC_NOTIFY_MIN_REPEAT", "300"))

_lock = threading.Lock()
_last_sent: dict[tuple[str, str], float] = {}
_last_state: dict[str, str] = {}


def _ps_quote(value: str) -> str:
    """Quote a value for a PowerShell single-quoted literal.

    Single-quoted PowerShell strings have exactly one escape: a doubled
    quote. No backslash processing, no subexpression evaluation -- which is
    precisely why this and not double quotes. Subsystem titles are ours, but
    the body carries provider names, launcher paths and exception text
    straight from the environment; `$(...)` inside a double-quoted string
    would execute.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _build_script(title: str, body: str) -> str:
    """WinRT toast with a NotifyIcon balloon fallback, as one script.

    XML is assembled from ToastText02's own template rather than a
    hand-written document so the shell always gets a shape it accepts; the
    text nodes are filled via the DOM (never string-concatenated) so a
    function name containing `<` or `&` cannot produce invalid XML and
    silently drop the alert.
    """
    t, b = _ps_quote(title), _ps_quote(body)
    return f"""
$ErrorActionPreference = 'Stop'
$title = {t}
$body  = {b}
try {{
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime]
    $tmpl = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
        [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $nodes = $tmpl.GetElementsByTagName('text')
    $nodes.Item(0).AppendChild($tmpl.CreateTextNode($title)) | Out-Null
    $nodes.Item(1).AppendChild($tmpl.CreateTextNode($body))  | Out-Null
    $toast = [Windows.UI.Notifications.ToastNotification]::new($tmpl)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(
        '{_POWERSHELL_APP_ID}').Show($toast)
}} catch {{
    # Fallback: balloon tip. Needs the process to outlive the animation, so
    # the sleep is load-bearing, not politeness.
    try {{
        Add-Type -AssemblyName System.Windows.Forms
        $icon = New-Object System.Windows.Forms.NotifyIcon
        $icon.Icon = [System.Drawing.SystemIcons]::Warning
        $icon.BalloonTipTitle = $title
        $icon.BalloonTipText  = $body
        $icon.Visible = $true
        $icon.ShowBalloonTip(10000)
        Start-Sleep -Seconds 11
        $icon.Dispose()
    }} catch {{ }}
}}
""".strip()


def send(title: str, body: str) -> bool:
    """Fire a desktop notification. Returns whether a send was *attempted*.

    Detached and non-blocking: we never wait on PowerShell, so a hung shell
    costs one orphaned process rather than a stalled health monitor. That
    also means delivery is genuinely unverifiable from here -- the banner and
    the log line remain the authoritative record, and this is the nudge.
    """
    if not NOTIFY_ENABLED or not sys.platform.startswith("win"):
        return False
    try:
        creation = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            # Without this an elevated dashboard flashes a console window on
            # every alert, which is its own small annoyance at 3am.
            creation |= subprocess.CREATE_NO_WINDOW
        subprocess.Popen(
            [_PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", _build_script(title, body)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, creationflags=creation,
        )
        return True
    except Exception:
        return False


def notify_transition(subsystem: str, state: str, title: str, body: str) -> bool:
    """Notify only when `subsystem` ENTERS a state it was not already in.

    The monitors call this on every poll; edge-triggering lives here so no
    caller has to keep its own "did I already say this" flag. Returns whether
    a notification was actually sent.
    """
    now = time.monotonic()
    with _lock:
        if _last_state.get(subsystem) == state:
            return False
        key = (subsystem, state)
        last = _last_sent.get(key)
        _last_state[subsystem] = state
        if last is not None and (now - last) < _MIN_REPEAT_SEC:
            # State genuinely changed, but we said this same thing moments
            # ago -- a dependency flapping down/up/down. Record the state so
            # the next real transition is still edge-detected, and stay quiet.
            return False
        _last_sent[key] = now
    return send(title, body)


def reset_for_tests() -> None:
    """Clear edge-detection memory. Test-support only."""
    with _lock:
        _last_sent.clear()
        _last_state.clear()
