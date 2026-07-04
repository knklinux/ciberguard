"""Command-line interface for CyberGuard.

This module exposes two ``argparse`` sub-commands (``offensive`` and
``defensive``) plus a top-level ``--version`` switch.  No external
dependencies are required - the CLI is purely ``stdlib``.

Typical use::

    python main.py offensive --target 192.0.2.10 --ports 22,80,443
    python main.py defensive --sshd-config /etc/ssh/sshd_config --report out.txt
    python main.py --version
"""

from __future__ import annotations

import argparse
import enum
import sys
from typing import Optional, Sequence

from . import __version__
from .config import DefCliDefaults, OffCliDefaults
from .defensive import print_report as print_audit
from .defensive import run_defensive
from .offensive import NmapScanner, SearchsploitSearcher, run_offensive
from .offensive import print_report as print_scan
from .utils import banner, error, info, warning


# ----------------------------------------------------------------------
# Exit codes (used by CI/CD integrations)
# ----------------------------------------------------------------------

class ExitCode(enum.IntEnum):
    """Single source of truth for CLI exit codes."""

    OK = 0
    VULNERABLE_OR_NO_OPEN_PORTS = 1
    AUDIT_PARTIAL = 2
    USAGE_ERROR = 64
    INTERRUPTED = 130


# ----------------------------------------------------------------------
# Argument parser construction
# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level :class:`argparse.ArgumentParser`."""
    parser = argparse.ArgumentParser(
        prog="cyberguard",
        description=(
            "CyberGuard - modular CLI security toolkit.\n"
            "Provides offensive (scan/exploit lookup) and defensive "
            "(host hardening audit) automation modules."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"cyberguard {__version__}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Increase output verbosity.",
    )

    sub = parser.add_subparsers(
        title="modules",
        dest="module",
        required=True,
        metavar="<module>",
    )

    # ---- offensive ---------------------------------------------------
    off = sub.add_parser(
        "offensive",
        help="Run nmap + searchsploit against a target.",
        description=(
            "Run nmap (service/version detection) against a target host, "
            "parse the resulting XML, and automatically feed discovered "
            "service banners into searchsploit."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    off.add_argument(
        "-t", "--target",
        required=True,
        help="Target host or IP address (e.g. 192.0.2.10 or scanme.nmap.org).",
    )
    off.add_argument(
        "-p", "--ports",
        default=OffCliDefaults.default_ports,
        help=(
            "Port specification passed to nmap "
            "(default: %(default)s). Examples: '22,80,443', '1-65535', "
            "'T:80,U:53'."
        ),
    )
    off.add_argument(
        "-o", "--output-dir",
        default="cyberguard_offensive",
        help="Directory to write XML reports into (default: %(default)s).",
    )
    off.add_argument(
        "--nmap-binary",
        default=OffCliDefaults.nmap_binary,
        help="Path/alias of the nmap binary (default: %(default)s).",
    )
    off.add_argument(
        "--searchsploit-binary",
        default=OffCliDefaults.searchsploit_binary,
        help="Path/alias of the searchsploit binary (default: %(default)s).",
    )
    off.add_argument(
        "--timeout",
        type=int,
        default=OffCliDefaults.timeout_seconds,
        help="Max nmap runtime in seconds (default: %(default)s).",
    )
    off.add_argument(
        "--no-searchsploit",
        action="store_true",
        help="Skip the searchsploit feed - only run the nmap scan.",
    )

    # ---- defensive ---------------------------------------------------
    deff = sub.add_parser(
        "defensive",
        help="Audit local host security settings.",
        description=(
            "Audit sysctl kernel parameters and sshd_config against a "
            "hardening baseline. Read-only - never modifies the system."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    deff.add_argument(
        "-c", "--sshd-config",
        default=DefCliDefaults.sshd_config_path,
        help="Path to sshd_config (default: %(default)s).",
    )
    deff.add_argument(
        "-r", "--report",
        default=None,
        help="Optional path to write the full text audit report to.",
    )

    return parser


# ----------------------------------------------------------------------
# Dispatch
# ----------------------------------------------------------------------

def _run_offensive_cmd(args: argparse.Namespace) -> int:
    """Execute the ``offensive`` subcommand and return an exit code.

    Exit codes
    ----------
    * ``0``  - scan completed and at least one port was found.
    * ``1``  - scan completed but no open ports (or scan completed with
               the binary just barely running).
    * ``64`` - usage error (e.g. empty ``--ports``).
    """
    if args.ports.strip() == "":
        error("--ports must not be empty.")
        return ExitCode.USAGE_ERROR

    scanner = NmapScanner(binary=args.nmap_binary, timeout=args.timeout)
    searcher = (
        SearchsploitSearcher(binary=args.searchsploit_binary)
        if not args.no_searchsploit
        else None
    )

    report = run_offensive(
        target=args.target,
        ports=args.ports,
        output_dir=args.output_dir,
        scanner=scanner,
        searcher=searcher,
        enable_searchsploit=not args.no_searchsploit,
    )

    print_scan(report)

    if report.open_ports > 0:
        return ExitCode.OK
    return ExitCode.VULNERABLE_OR_NO_OPEN_PORTS


def _run_defensive_cmd(args: argparse.Namespace) -> int:
    """Execute the ``defensive`` subcommand and return an exit code.

    Exit codes (precedence: high → low):

    * ``2``  - auditor was partially blinded (any error findings).
    * ``1``  - at least one vulnerable setting.
    * ``0``  - all clean.
    """
    report = run_defensive(
        sshd_config_path=args.sshd_config,
        output_path=args.report,
    )
    print_audit(report)

    if report.error_count > 0:
        return ExitCode.AUDIT_PARTIAL
    if report.vulnerable_count > 0:
        return ExitCode.VULNERABLE_OR_NO_OPEN_PORTS
    return ExitCode.OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point expected by ``python -m cyberguard`` and ``main.py``."""
    parser = build_parser()
    args = parser.parse_args(argv)

    banner(f"CyberGuard v{__version__}")
    if args.verbose:
        info("Verbose mode enabled.")

    try:
        if args.module == "offensive":
            return _run_offensive_cmd(args)
        if args.module == "defensive":
            return _run_defensive_cmd(args)
    except KeyboardInterrupt:
        warning("Interrupted by user.")
        return ExitCode.INTERRUPTED

    # argparse with ``required=True`` guarantees we never reach here.
    error("No module specified.")
    return ExitCode.USAGE_ERROR  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
