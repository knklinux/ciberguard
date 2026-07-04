"""Shared utilities: terminal styling, safe subprocess execution, XML parsing.

These helpers are intentionally framework-free (no rich / colorama dependency)
so the tool runs on minimal Python installs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec - used intentionally for nmap/searchsploit invocation.
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple


# ----------------------------------------------------------------------
# Terminal styling (ANSI)
# ----------------------------------------------------------------------

# Only emit ANSI escape sequences when we are attached to a TTY.
_ENABLE_ANSI = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class Color(str, Enum):
    """ANSI colour tokens used by :func:`style` and the report renderers.

    Defined as a public :class:`enum.Enum` so that downstream submodules
    can import a stable symbol (avoiding the "leaky private-API" problem
    of importing ``_Style`` directly).
    """

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def style(text: str, color: Color | str, *, bold: bool = False) -> str:
    """Wrap ``text`` with ANSI color codes when a TTY is available."""
    if not _ENABLE_ANSI:
        return text
    prefix = (Color.BOLD.value if bold else "") + str(color)
    return f"{prefix}{text}{Color.RESET.value}"


def info(msg: str) -> None:
    print(style(f"[i] {msg}", Color.BLUE, bold=True))


def success(msg: str) -> None:
    print(style(f"[+] {msg}", Color.GREEN, bold=True))


def warning(msg: str) -> None:
    print(style(f"[!] {msg}", Color.YELLOW, bold=True))


def error(msg: str) -> None:
    print(style(f"[-] {msg}", Color.RED, bold=True), file=sys.stderr)


def banner(title: str) -> None:
    """Print a section divider banner (78 chars wide)."""
    bar = "=" * 78
    print(style(bar, Color.CYAN))
    print(style(f"  {title}", Color.CYAN, bold=True))
    print(style(bar, Color.CYAN))


# ----------------------------------------------------------------------
# Subprocess helpers
# ----------------------------------------------------------------------

@dataclass
class CommandResult:
    """Normalized result of a subprocess invocation."""

    returncode: int
    stdout: str
    stderr: str
    cmd: Sequence[str] = field(default_factory=list)


def require_tool(name: str) -> None:
    """Exit with a friendly error if ``name`` is missing on PATH."""
    if shutil.which(name) is None:
        error(
            f"Required external tool '{name}' not found on PATH. "
            f"Install it or adjust your environment."
        )
        sys.exit(2)


def run_command(
    cmd: Sequence[str],
    *,
    timeout: Optional[int] = None,
    check: bool = False,
    input_text: Optional[str] = None,
) -> CommandResult:
    """Run ``cmd`` and capture output safely.

    ``subprocess.run`` with ``shell=False`` is used so arguments are passed
    as a list (no shell-injection surface). The ``# nosec`` on the import
    above documents the deliberate use of subprocess.
    """
    try:
        completed = subprocess.run(  # nosec - shell=False, args passed as list
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Executable not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc

    result = CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        cmd=list(cmd),
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result


# ----------------------------------------------------------------------
# Nmap XML parsing
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class NmapService:
    """A single service discovered by nmap."""

    host: str
    port: int
    protocol: str
    state: str
    name: str
    product: str
    version: str
    extra_info: str

    @property
    def banner(self) -> str:
        """Stable ``name/version`` string used as searchsploit query input."""
        parts = [self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(p for p in parts if p).strip()

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "banner": self.banner,
        }


@dataclass(frozen=True)
class NmapScriptHit:
    """A single ``<script>`` element from a nmap XML report.

    nmap ``-sC`` runs the default script set, which can surface real
    vulnerability hints (e.g. ``vulners``, ``vuln``, ``ssl-cert``). These
    are surfaced here so the report consumer doesn't lose them.

    ``port`` is ``None`` for host-level scripts (``<hostscript><script .../>``)
    and a positive integer for port-scoped scripts.
    """

    script_id: str
    output: str
    port: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "id": self.script_id,
            "output": self.output,
            "port": self.port,
        }


def parse_nmap_xml(path: os.PathLike | str) -> Tuple[List[NmapService], List[NmapScriptHit]]:
    """Parse a nmap XML report.

    Returns a tuple ``(services, scripts)``:

    * ``services``  - open TCP/UDP services with parsed ``<service>`` fields.
    * ``scripts``   - every ``<script id=… output=…>`` element, with the
      enclosing port (when relevant) attached.

    Raises :class:`FileNotFoundError` / :class:`ET.ParseError` for I/O /
    malformed XML problems so callers can decide how to surface them.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    services: List[NmapService] = []
    scripts: List[NmapScriptHit] = []

    for host_el in root.findall("host"):
        # Resolve the host address (IPv4 preferred, fallback to address@addr).
        address_el = host_el.find("address")
        if address_el is None:
            continue
        host_addr = address_el.get("addr", "")

        # Skip hosts that did not come back as 'up'.
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_id_raw = port_el.get("portid", "0") or "0"
                try:
                    port_num = int(port_id_raw)
                except ValueError:
                    # Skip garbage portids instead of emitting port=0.
                    continue
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""

                # Build script hits regardless of state (scripts may run on
                # filtered/closed ports and still report useful info).
                for s_el in port_el.findall("script"):
                    scripts.append(
                        NmapScriptHit(
                            script_id=s_el.get("id", "unknown"),
                            output=s_el.get("output", "") or "",
                            port=port_num,
                        )
                    )

                # We only emit a service record for *open* ports.
                if state != "open":
                    continue

                service_el = port_el.find("service")
                if service_el is None:
                    continue

                services.append(
                    NmapService(
                        host=host_addr,
                        port=port_num,
                        protocol=protocol,
                        state=state,
                        name=service_el.get("name", "") or "",
                        product=service_el.get("product", "") or "",
                        version=service_el.get("version", "") or "",
                        extra_info=service_el.get("extrainfo", "") or "",
                    )
                )

        # Host-level scripts (``<hostscript>``).
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            for s_el in hostscript_el.findall("script"):
                scripts.append(
                    NmapScriptHit(
                        script_id=s_el.get("id", "unknown"),
                        output=s_el.get("output", "") or "",
                        port=None,
                    )
                )

    return services, scripts


# ----------------------------------------------------------------------
# Misc helpers
# ----------------------------------------------------------------------

def ensure_directory(path: os.PathLike | str) -> Path:
    """Create ``path`` (and parents) if missing and return it as :class:`Path`."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def truncate(text: str, width: int = 80) -> str:
    """Trim ``text`` to ``width`` characters with an ellipsis when needed."""
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def iter_nonempty(lines: Iterable[str]) -> List[str]:
    """Helper that flattens + filters blank lines from an iterable of strings."""
    return [ln.rstrip() for ln in lines if ln and ln.strip()]


def parse_searchsploit_json(stdout: str) -> Optional[List[dict]]:
    """Best-effort parse of ``searchsploit --format json`` output.

    Returns a list of ``{"title": ..., "path": ...}`` dicts on success or
    ``None`` if the payload cannot be decoded / doesn't match the expected
    schema. Callers must fall back to text-mode parsing when ``None`` is
    returned.
    """
    if not stdout or not stdout.strip():
        return None
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None

    # The modern searchsploit JSON shape is:
    #   {"SEARCHSPLOIT": ...,
    #    "RESULTS_EXPLOIT": [{"Title": ..., "Path": ..., ...}, ...],
    #    "RESULTS_SHELLCODE": [...]
    # Reference: https://www.exploit-db.com/searchsploit
    rows = payload.get("RESULTS_EXPLOIT") if isinstance(payload, dict) else None
    if rows is None:
        # Some older invocations emit only `RESULTS_EXPLOIT` at the top
        # level when the wrapper key is absent.
        rows = payload.get("RESULTS_EXPLOIT")
        if rows is None:
            return None

    if not isinstance(rows, list):
        return None

    parsed: List[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        title = str(row.get("Title", "") or "").strip()
        path = str(row.get("Path", "") or "").strip()
        if not title or not path:
            continue
        parsed.append({"title": title, "path": path})
    # Return the list - possibly empty - so callers can distinguish a
    # valid-but-empty payload from a parse / schema failure (None).
    return parsed


__all__ = [
    "Color",
    "style",
    "info",
    "success",
    "warning",
    "error",
    "banner",
    "CommandResult",
    "require_tool",
    "run_command",
    "NmapService",
    "NmapScriptHit",
    "parse_nmap_xml",
    "ensure_directory",
    "truncate",
    "iter_nonempty",
    "parse_searchsploit_json",
]
