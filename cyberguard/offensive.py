"""Offensive automation - eJPT / scanning module.

This module orchestrates an end-to-end scan-to-exploit pipeline:

1. Run nmap with service & version detection against a target host.
2. Persist results as XML so they can be archived / re-parsed.
3. Programmatically parse the XML - both ``<service>`` and ``<script>``
   elements (``-sC`` results) - and extract NSE findings.
4. Feed every service ``name product version`` triple into
   ``searchsploit`` to surface known public exploits.

Only run this against systems you own or have **explicit written
authorization** to test.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utcnow_naive() -> datetime:
    """Return naive UTC datetime.

    Equivalent to the (Python-3.12-deprecated) ``datetime.utcnow()`` but
    future-proof. Returns a *naive* datetime so the existing formatting
    helpers (which append ``Z`` manually) keep working unchanged.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
from pathlib import Path
from typing import Dict, List, Optional

from .config import OffCliDefaults
from .utils import (
    Color,
    CommandResult,
    NmapScriptHit,
    NmapService,
    banner,
    error,
    ensure_directory,
    info,
    parse_nmap_xml,
    parse_searchsploit_json,
    require_tool,
    run_command,
    style,
    success,
    truncate,
    warning,
)


# ----------------------------------------------------------------------
# Data containers
# ----------------------------------------------------------------------

@dataclass
class ExploitHit:
    """A single searchsploit match for a given service banner.

    Mutability is intentional – :meth:`run_offensive` decorates each
    ``Query`` with the originating ``(host,port,proto)`` tag *before* the
    instance is added to the report. The dataclass is therefore plain,
    not ``frozen=True``.
    """

    query: str
    title: str
    path: str

    @property
    def short_path(self) -> str:
        return truncate(self.path, 70)


@dataclass
class ScanReport:
    """Aggregate result returned by :func:`run_offensive`.

    New fields added in recent versions are populated via
    ``default_factory`` so manual ``ScanReport(...)`` instantiations
    remain backward compatible.
    """

    target: str
    ports: str
    xml_path: Path
    raw: CommandResult
    services: List[NmapService] = field(default_factory=list)
    exploits: List[ExploitHit] = field(default_factory=list)
    scripts: List[NmapScriptHit] = field(default_factory=list)
    # Per-service map keyed by the *frozen* NmapService instance –
    # no string-key collisions, no dataclass mutation.
    service_exploits: Dict[NmapService, List[ExploitHit]] = field(default_factory=dict)
    started_at: datetime = field(default_factory=_utcnow_naive)
    finished_at: Optional[datetime] = None

    @property
    def open_ports(self) -> int:
        return sum(1 for s in self.services if s.state == "open")

    @property
    def services_with_exploit(self) -> int:
        return len(self.exploits)


# ----------------------------------------------------------------------
# Nmap wrapper
# ----------------------------------------------------------------------

class NmapScanner:
    """High-level wrapper around the ``nmap`` CLI.

    The constructor accepts per-instance overrides of all defaults so it
    can be unit-tested without invoking a real binary.
    """

    def __init__(
        self,
        binary: str = OffCliDefaults.nmap_binary,
        flags: tuple = OffCliDefaults.nmap_flags,
        timeout: int = OffCliDefaults.timeout_seconds,
    ) -> None:
        self.binary = binary
        self.flags = tuple(flags)
        self.timeout = timeout

    def build_command(self, target: str, ports: str, xml_output: Path) -> List[str]:
        """Build the nmap command line (keeps option ordering deterministic)."""
        cmd: List[str] = [self.binary]
        # Ability to override single target's port range via '-p'.
        cmd += ["-p", ports]
        cmd += list(self.flags)
        cmd += ["-oX", str(xml_output), target]
        return cmd

    def scan(
        self,
        target: str,
        *,
        ports: str = OffCliDefaults.default_ports,
        output_dir: os.PathLike | str = ".",
        file_stem: Optional[str] = None,
    ) -> tuple[Path, CommandResult]:
        """Execute the scan, returning ``(xml_path, raw_result)``.

        ``file_stem`` lets callers override the default file name, which is
        useful when embedding cyberguard inside larger pipelines.
        """
        require_tool(self.binary)

        if not target or target.strip() == "":
            raise ValueError("Target host/IP must not be empty.")

        # /etc/hosts / DNS quirks aside, nmap will still complain, but we
        # save the user a confusing nmap error early when input is bad.
        if any(c in target for c in (" ", "\t", "\n")):
            raise ValueError(f"Target contains whitespace: {target!r}")

        out_dir = ensure_directory(output_dir)
        stem = file_stem or f"nmap_{target.replace('/', '_')}_{_utcnow_naive():%Y%m%dT%H%M%S}"
        xml_path = out_dir / f"{stem}.xml"

        cmd = self.build_command(target, ports, xml_path)
        info(f"Executing: {' '.join(cmd)}")

        raw = run_command(cmd, timeout=self.timeout)
        if raw.returncode != 0:
            warning(f"nmap exited with code {raw.returncode}")
            if raw.stderr.strip():
                warning(f"nmap stderr: {raw.stderr.strip().splitlines()[0]}")

        if not xml_path.exists():
            raise RuntimeError(f"nmap did not produce XML output at {xml_path}")

        return xml_path, raw


# ----------------------------------------------------------------------
# Searchsploit wrapper
# ----------------------------------------------------------------------

class SearchsploitSearcher:
    """High-level wrapper around the ``searchsploit`` CLI.

    Searchsploit (part of the ExploitDB package) typically lives at
    ``/usr/bin/searchsploit`` and searches a local copy of the Exploit
    Database archive. No internet access is required.

    Parsing strategy (in order):

    1. Add ``--format json`` and try :func:`parse_searchsploit_json`.
    2. If JSON parsing fails, fall back to the legacy pipe-delimited
       table format.
    """

    def __init__(
        self,
        binary: str = OffCliDefaults.searchsploit_binary,
        timeout: int = 120,
    ) -> None:
        self.binary = binary
        self.timeout = timeout

    def query(self, banner_str: str) -> List[ExploitHit]:
        """Run ``searchsploit --nmap`` for ``banner_str`` and return matches."""
        if not banner_str.strip():
            return []

        # ``--nmap`` keeps filter semantics compatible with our XML output.
        # ``--format json`` is the only format we trust for stable parsing;
        # ``--disable-colour`` keeps ANSI codes out of our stdout in both
        # JSON and legacy modes.
        cmd = [self.binary, "--nmap", "--disable-colour", "--format", "json", banner_str]
        try:
            result = run_command(cmd, timeout=self.timeout)
        except RuntimeError as exc:
            warning(str(exc))
            return []

        # 1) JSON parsing first.
        parsed_json = parse_searchsploit_json(result.stdout)
        if parsed_json is not None:
            return [
                ExploitHit(query=banner_str, title=row["title"], path=row["path"])
                for row in parsed_json
            ]

        # 2) Fallback: re-run without ``--format json`` so the legacy
        # printer kicks in and we can reuse the column heuristic. We do
        # not fail loudly here - some searchsploit builds pre-date the
        # JSON flag and we want to be tolerant.
        try:
            fallback = run_command(
                [self.binary, "--nmap", "--disable-colour", banner_str],
                timeout=self.timeout,
            )
        except RuntimeError as exc:
            warning(str(exc))
            return []
        return self._parse_legacy_output(banner_str, fallback.stdout)

    # We only treat the *exact* canonical header label as a header row.
    # Including bare ``"path"`` / ``"title"`` would silently drop legitimate
    # exploits whose title happens to start with those words ("Path traversal
    # in Apache httpd", etc.), so the label set is deliberately minimal.
    _LEGACY_HEADER_LABELS = frozenset({"exploit title"})
    # Pre-compiled separator regex used in place of per-cell `set` membership
    # tests on `_LEGACY_SEPARATOR_CHARS` for ~O(n_lines) instead of
    # ~O(n_lines × n_cells) allocations.
    _LEGACY_SEPARATOR_RE = re.compile(r"^[-=*|+ ]+$")
    # searchsploit verbose mode emits a descriptor row whose first cell is
    # literally ``"("`` (sometimes ``"(|"``). We deliberately scope
    # detection to those exact prefixes so that real ExploitDB titles
    # containing ``(`` or ``[`` (e.g. ``(CVE-2024-...) Apache httpd RCE``)
    # are not mis-classified as descriptor rows.
    _LEGACY_DESCRIPTOR_PREFIXES = frozenset({"(", "(|"})

    @classmethod
    def _is_legacy_descriptor_row(cls, non_empty: List[str]) -> bool:
        """True for ``(  | Description)`` style row markers used by
        searchsploit's verbose ``--nmap`` output.
        """
        return non_empty[0] in cls._LEGACY_DESCRIPTOR_PREFIXES

    @classmethod
    def _is_legacy_separator_row(cls, non_empty: List[str]) -> bool:
        """True when every cell contains only separator characters.

        Tested against ``"".join(non_empty)`` instead of per-cell set
        membership so a single regex match decides a row - cheaper than
        allocating one ``set`` per cell per row.
        """
        return bool(cls._LEGACY_SEPARATOR_RE.match("".join(non_empty)))

    @classmethod
    def _parse_legacy_output(cls, query: str, raw: str) -> List[ExploitHit]:
        """Tolerant parser for ``searchsploit``'s old tabular layout.

        ``searchsploit`` emits a 2-row header followed by zero or more
        ``|``-delimited rows. Header detection is performed on *cells*
        (not the raw line) so that the regex works whether or not the
        header line is glued to the path cell by a pipe separator:
        e.g. ``  Exploit Title      | Path``.

        Separator lines are recognised by the per-cell character set
        rather than an end-anchored regex, which also makes it tolerant
        of dash/pipe dividers of variable widths.
        """
        hits: List[ExploitHit] = []
        seen: set[str] = set()
        for raw_line in raw.splitlines():
            line = raw_line.rstrip()
            if not line or "|" not in line:
                continue
            if line in seen:
                continue
            seen.add(line)

            cells = [c.strip() for c in line.split("|")]
            non_empty = [c for c in cells if c]
            if len(non_empty) < 2:
                continue

            first_label = non_empty[0].lower()
            if first_label in cls._LEGACY_HEADER_LABELS:
                continue
            if cls._is_legacy_separator_row(non_empty):
                continue
            if cls._is_legacy_descriptor_row(non_empty):
                continue

            hits.append(ExploitHit(query=query, title=non_empty[0], path=non_empty[-1]))

        return hits


# ----------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------

def run_offensive(
    target: str,
    *,
    ports: str = OffCliDefaults.default_ports,
    output_dir: os.PathLike | str = ".",
    scanner: Optional[NmapScanner] = None,
    searcher: Optional[SearchsploitSearcher] = None,
    enable_searchsploit: bool = True,
    verbose: bool = True,
) -> ScanReport:
    """End-to-end pipeline: nmap -> xml -> searchsploit.

    Returned :class:`ScanReport` lets the caller decide how to render,
    serialize or further process the results.

    Parameters
    ----------
    enable_searchsploit:
        When ``False``, the searchsploit feed (and the
        :func:`require_tool` guard for the binary) is skipped entirely.
        Useful for CI runs that only want the nmap archive.
    """
    scanner = scanner or NmapScanner()
    if enable_searchsploit and searcher is None:
        searcher = SearchsploitSearcher()

    banner("Offensive module :: scan + exploit lookup")

    info(f"Target   : {target}")
    info(f"Port set : {ports}")
    info(f"Out dir  : {output_dir}")
    info(f"Searchsploit feed : {'enabled' if enable_searchsploit else 'disabled'}")

    xml_path, raw = scanner.scan(target, ports=ports, output_dir=output_dir)

    # ---- Parse XML ------------------------------------------------------
    try:
        services, scripts = parse_nmap_xml(xml_path)
    except (FileNotFoundError, ET.ParseError) as exc:
        error(f"Failed to parse nmap XML: {exc}")
        services, scripts = [], []

    if verbose:
        print()
        if not services:
            warning("No open services were enumerated.")
        else:
            info(f"Found {len(services)} open service(s):")
            for svc in services:
                tag = f"{svc.host}:{svc.port}/{svc.protocol}"
                print(
                    f"    {style(tag, Color.MAGENTA, bold=True)} -> "
                    f"{style(svc.banner or '(no banner)', Color.GREEN)}"
                )
        if scripts:
            info(f"NSE surfaced {len(scripts)} script finding(s) (see report).")

    # ---- Searchsploit ---------------------------------------------------
    service_exploits: Dict[NmapService, List[ExploitHit]] = {}
    if enable_searchsploit and services:
        require_tool(searcher.binary)
        print()
        info("Querying local exploit-db archive via searchsploit...")

        for svc in services:
            if not svc.banner:
                continue
            hits = searcher.query(svc.banner)
            if not hits:
                continue
            tag = f"[{svc.host}:{svc.port}/{svc.protocol}] {svc.banner}"
            decorated: List[ExploitHit] = []
            for hit in hits:
                # Decorating ``query`` rebuilds the ExploitHit so we don't
                # mutate the searcher-produced originals.
                decorated.append(
                    ExploitHit(query=tag, title=hit.title, path=hit.path)
                )
                if verbose:
                    print(
                        f"    {style(hit.short_path, Color.RED)} :: "
                        f"{hit.title}"
                    )
            service_exploits[svc] = decorated

    # Flatten dict for the legacy ``exploits`` list (preserved for back-
    # compat with downstream consumers that only read a linear list).
    all_hits: List[ExploitHit] = []
    for hits in service_exploits.values():
        all_hits.extend(hits)

    report = ScanReport(
        target=target,
        ports=ports,
        xml_path=xml_path,
        raw=raw,
        services=services,
        exploits=all_hits,
        scripts=scripts,
        service_exploits=service_exploits,
        finished_at=_utcnow_naive(),
    )

    print()
    success(
        f"Scan complete: {report.open_ports} open port(s); "
        f"{report.services_with_exploit} exploit-db hit(s); "
        f"{len(scripts)} NSE finding(s)."
    )
    info(f"XML archive: {xml_path}")

    return report


# ----------------------------------------------------------------------
# Pretty-print the report to stdout (used by the CLI)
# ----------------------------------------------------------------------

def print_report(report: ScanReport) -> None:
    """Render a :class:`ScanReport` as a human-friendly summary table."""
    banner(f"Scan report :: {report.target}")
    info(f"Started  : {report.started_at.isoformat()}Z")
    if report.finished_at:
        delta = (report.finished_at - report.started_at).total_seconds()
        info(f"Duration : {delta:.1f}s")
    info(f"Open ports : {report.open_ports}")
    info(f"Exploits   : {report.services_with_exploit}")
    info(f"NSE hits   : {len(report.scripts)}")
    print()

    info("Services")
    if not report.services:
        warning("  (none)")
    else:
        for svc in report.services:
            line = (
                f"  {svc.host:<15} {svc.port:>5}/{svc.protocol:<4} "
                f"{svc.state:<6} {svc.banner}"
            )
            print(style(line, Color.GREEN))

    print()
    info("Exploit-db matches")
    if not report.exploits:
        warning("  (no searchsploit matches)")
    else:
        for hit in report.exploits:
            line = f"  {hit.query or hit.title}  --  {hit.short_path}"
            print(style(line, Color.RED))

    print()
    info("NSE script findings")
    if not report.scripts:
        warning("  (no -sC output surfaced)")
    else:
        for s in report.scripts:
            port = s.port if s.port is not None else "*"
            print(
                f"  {style(str(port), Color.MAGENTA, bold=True)}  "
                f"{style(s.script_id, Color.YELLOW, bold=True)}  "
                f"{truncate(s.output, 64)}"
            )


__all__ = [
    "ExploitHit",
    "ScanReport",
    "NmapScanner",
    "SearchsploitSearcher",
    "run_offensive",
    "print_report",
]
