"""Defensive automation - SOC / hardening auditor.

This module performs a *read-only* audit of host security settings:

* Inspect ``/proc/sys/...`` sysctl values against a CIS-style baseline.
* Parse ``/etc/ssh/sshd_config`` against an opinionated baseline.

The result is a structured :class:`AuditReport` that callers (CLI,
JSON exporter, web dashboard, ...) can render however they want.

The auditor never mutates system state. Remediation is out of scope;
operators must apply fixes via a change-management process.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

from .config import (
    KERNEL_BASELINE,
    SEVERITY_ORDER,
    SSHD_BASELINE,
    SSHD_CONFIG_DEFAULT,
    SYSCTL_PROC_ROOT,
    SafeValues,
)
from .utils import (
    Color,
    banner,
    info,
    style,
    success,
    warning,
)


# ----------------------------------------------------------------------
# Data containers
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """A single compliance check result.

    ``setting``     - human-readable name (kernel key or ssh directive).
    ``observed``    - the value we found on the host ('' = absent/error).
    ``expected``    - the safe value(s) we expect.
    ``status``      - ``safe`` | ``vulnerable`` | ``info`` | ``error``.
    ``severity``    - ``critical`` | ``high`` | ``medium`` | ``low`` | ``info``.
    ``description`` - short rationale / recommendation.
    """

    module: str
    setting: str
    observed: str
    expected: str
    status: str
    severity: str
    description: str = ""

    @property
    def is_compliant(self) -> bool:
        return self.status == "safe"


@dataclass
class AuditReport:
    """Aggregated result of a defensive run."""

    findings: List[Finding] = field(default_factory=list)

    def by_status(self, status: str) -> List[Finding]:
        return [f for f in self.findings if f.status == status]

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def compliant_count(self) -> int:
        return len(self.by_status("safe"))

    @property
    def vulnerable_count(self) -> int:
        return len(self.by_status("vulnerable"))

    @property
    def error_count(self) -> int:
        return len(self.by_status("error"))

    @property
    def total_count(self) -> int:
        return len(self.findings)


# ----------------------------------------------------------------------
# sysctl auditor
# ----------------------------------------------------------------------

class SysctlAuditor:
    """Read ``/proc/sys/<key>`` files and compare them to :data:`KERNEL_BASELINE`."""

    # Keys in KERNEL_BASELINE are dot-separated; /proc uses slashes.
    _DOT_TO_SLASH = staticmethod(lambda k: k.replace(".", "/"))

    def __init__(self, proc_root: Path = SYSCTL_PROC_ROOT) -> None:
        self.proc_root = proc_root

    def read_value(self, key: str) -> Optional[str]:
        """Return the trimmed file content or ``None`` if unreadable."""
        path = self.proc_root / self._DOT_TO_SLASH(key)
        try:
            return path.read_text(encoding="utf-8", errors="replace").strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def audit(self) -> List[Finding]:
        findings: List[Finding] = []
        for key, expected in KERNEL_BASELINE.items():
            observed = self.read_value(key)
            if observed is None:
                findings.append(
                    Finding(
                        module="sysctl",
                        setting=key,
                        observed="<unreadable>",
                        expected="/".join(str(e) for e in expected),
                        status="error",
                        severity="info",
                        description=(
                            "Could not read /proc/sys entry "
                            "(missing or insufficient privileges)."
                        ),
                    )
                )
                continue

            try:
                observed_int = int(observed)
            except ValueError:
                observed_int = None  # type: ignore[assignment]

            compliant = False
            if observed_int is not None:
                compliant = any(observed_int == e for e in expected)

            findings.append(
                Finding(
                    module="sysctl",
                    setting=key,
                    observed=observed,
                    expected="/".join(str(e) for e in expected),
                    status="safe" if compliant else "vulnerable",
                    severity="medium" if not compliant else "info",
                    description=(
                        "Secure baseline (CIS/NIST-inspired)."
                        if compliant
                        else "Value deviates from hardened baseline - "
                        "consider remediating via sysctl(8) or drop-in file."
                    ),
                )
            )
        return findings


# ----------------------------------------------------------------------
# SSH auditor
# ----------------------------------------------------------------------

class SSHAuditor:
    """Parse ``sshd_config`` and compare directives against :data:`SSHD_BASELINE`.

    The parser is deliberately simple: directives are matched with a
    permissive regex that handles both ``Key Value`` and ``Key=Value`` forms.
    Quoted values are unquoted. ``#`` lines are treated as comments.

    First-occurrence-wins is our policy, which mirrors sshd's own behaviour
    for conflicting directives.

    `Match` blocks
    --------------
    When a ``Match`` directive is encountered, all subsequent lines are
    scoped to that conditional. The current auditor only emits findings
    for *global* directives, then records a single ``info``-level Finding
    informing the operator that conditional overrides were ignored. This
    guarantee avoids false-positive ``safe`` verdicts that would arise
    if we merged post-``Match`` directives into the global table.
    """

    _LINE_RE = re.compile(
        r"""
        ^\s*
        (?P<key>[A-Za-z][A-Za-z0-9_]*)   # directive name
        \s*[=\s]\s*                       # separator: '=' or whitespace
        (?P<val>.*?)
        \s*$
        """,
        re.VERBOSE,
    )

    def __init__(self, path: Path | str = SSHD_CONFIG_DEFAULT) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def parse(self) -> Tuple[Dict[str, str], bool]:
        """Return ``(directives, saw_match_block)``.

        ``directives`` is a ``{Directive: Value}`` map of the first
        occurrence of each *global* directive.
        ``saw_match_block`` is ``True`` when at least one ``Match``
        conditional was detected. In that case the returned directive
        map covers *only* the lines preceding the first ``Match``.
        """
        directives: Dict[str, str] = {}
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, PermissionError, OSError):
            return directives, False

        saw_match = False
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split("#", 1)[0].strip()  # strip in-line comments

            # Stop accumulating at the first Match block: directives below
            # this point only apply to the conditional scope.
            if line.lower().startswith("match"):
                saw_match = True
                break

            match = self._LINE_RE.match(line)
            if not match:
                continue
            key = match.group("key")
            val = match.group("val").strip().strip('"').strip("'")
            directives.setdefault(key, val)

        return directives, saw_match

    @staticmethod
    def _matches(observed: str, safe_values: SafeValues) -> bool:
        """Return ``True`` if ``observed`` (case-folded) is in ``safe_values``."""
        obs = observed.lower()
        if isinstance(safe_values, frozenset):
            return obs in safe_values
        return obs in tuple(v.lower() for v in safe_values)

    def audit(self) -> List[Finding]:
        if not self.exists():
            return [
                Finding(
                    module="sshd",
                    setting="<file>",
                    observed="<missing>",
                    expected=str(self.path),
                    status="error",
                    severity="info",
                    description=(
                        f"sshd_config not found at {self.path}. Skipping "
                        "SSH compliance checks. Use --sshd-config to override."
                    ),
                )
            ]

        directives, saw_match = self.parse()
        findings: List[Finding] = []

        for directive, (safe_values, severity, description) in SSHD_BASELINE.items():
            observed = directives.get(directive, "<unset>")

            if observed == "<unset>":
                findings.append(
                    Finding(
                        module="sshd",
                        setting=directive,
                        observed=observed,
                        expected=_format_expected(safe_values),
                        status="vulnerable",
                        severity=severity,
                        description=description
                        + " Note: directive is not set; sshd uses default.",
                    )
                )
                continue

            compliant = self._matches(observed, safe_values)
            findings.append(
                Finding(
                    module="sshd",
                    setting=directive,
                    observed=observed,
                    expected=_format_expected(safe_values),
                    status="safe" if compliant else "vulnerable",
                    severity=severity if not compliant else "info",
                    description=description,
                )
            )

        if saw_match:
            findings.append(
                Finding(
                    module="sshd",
                    setting="<Match blocks>",
                    observed="detected",
                    expected="n/a (requires conditional parsing)",
                    status="info",
                    severity="low",
                    description=(
                        "sshd_config contains one or more Match conditional "
                        "blocks. Per-Match directives were intentionally "
                        "ignored to avoid false positives - only the "
                        "global defaults were audited. Review Match blocks "
                        "manually for full coverage."
                    ),
                )
            )

        return findings


def _format_expected(safe_values: SafeValues) -> str:
    """Render a baseline ``safe_values`` container for human-readable output."""
    if isinstance(safe_values, frozenset):
        ints = sorted(int(v) for v in safe_values)
        if not ints:
            return ""
        # Cheap contiguous-range check: O(1) for the common case.
        if ints[-1] - ints[0] + 1 == len(ints):
            return f"{ints[0]}-{ints[-1]}"
        return "/".join(str(i) for i in ints[:6]) + ("…" if len(ints) > 6 else "")
    return "/".join(safe_values)


# ----------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------

def run_defensive(
    *,
    sshd_config_path: Path | str = SSHD_CONFIG_DEFAULT,
    output_path: Optional[Path | str] = None,
) -> AuditReport:
    """Run every defensive sub-auditor and aggregate results.

    If ``output_path`` is provided, a plain-text report is written in
    addition to the returned :class:`AuditReport`.
    """
    banner("Defensive module :: host hardening audit")

    report = AuditReport()
    sysauditor = SysctlAuditor()
    sshauditor = SSHAuditor(sshd_config_path)

    info("Auditing sysctl kernel parameters...")
    report.findings.extend(sysauditor.audit())

    info(f"Auditing sshd_config ({sshauditor.path})...")
    report.findings.extend(sshauditor.audit())

    # Sort: vulnerable first, then by severity, then alphabetically.
    sev_index = {s: i for i, s in enumerate(SEVERITY_ORDER)}

    def sort_key(f: Finding) -> Tuple[int, int, str]:
        not_safe = 0 if f.status == "safe" else 1
        return (not_safe, sev_index.get(f.severity, 99), f.setting)

    report.findings.sort(key=sort_key)

    # Console summary
    print()
    success(
        f"Audit complete: {report.compliant_count}/{report.total_count} safe, "
        f"{report.vulnerable_count} vulnerable, {report.error_count} unreadable."
    )

    if output_path:
        write_report(report, output_path)
        info(f"Detailed report written to: {output_path}")

    return report


# ----------------------------------------------------------------------
# Report formatting
# ----------------------------------------------------------------------

_SEVERITY_COLOR = {
    "critical": Color.RED,
    "high": Color.RED,
    "medium": Color.YELLOW,
    "low": Color.CYAN,
    "info": Color.DIM,
}

_STATUS_COLOR = {
    "safe": Color.GREEN,
    "vulnerable": Color.RED,
    "error": Color.YELLOW,
    "info": Color.DIM,
}


def write_report(report: AuditReport, path: Path | str) -> None:
    """Persist a plain-text audit report to ``path``."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    out = p.open("w", encoding="utf-8")
    with out:
        out.write("CyberGuard Defensive Audit Report\n")
        out.write("=" * 60 + "\n\n")
        out.write(
            f"Compliant  : {report.compliant_count}/{report.total_count}\n"
            f"Vulnerable : {report.vulnerable_count}\n"
            f"Errors     : {report.error_count}\n\n"
        )

        current_module: Optional[str] = None
        for f in report.findings:
            if f.module != current_module:
                out.write(f"\n[{f.module.upper()}]\n")
                out.write("-" * 60 + "\n")
                current_module = f.module

            out.write(
                f"  - {f.setting}\n"
                f"      status   : {f.status}\n"
                f"      severity : {f.severity}\n"
                f"      observed : {f.observed}\n"
                f"      expected : {f.expected}\n"
                f"      note     : {f.description}\n\n"
            )


def print_report(report: AuditReport) -> None:
    """Render the audit report as a colourised table to stdout."""
    banner("Defensive Audit Report")
    print(
        f"  Compliant: {style(str(report.compliant_count), Color.GREEN, bold=True)}"
        f"  Vulnerable: {style(str(report.vulnerable_count), Color.RED, bold=True)}"
        f"  Error: {style(str(report.error_count), Color.YELLOW, bold=True)}"
        f"  Total: {report.total_count}\n"
    )

    current_module: Optional[str] = None
    for f in report.findings:
        if f.module != current_module:
            print(style(f"\n[{f.module.upper()}]", Color.CYAN, bold=True))
            current_module = f.module

        status_color = _STATUS_COLOR.get(f.status, Color.DIM)
        sev_color = _SEVERITY_COLOR.get(f.severity, Color.DIM)
        print(
            f"  {style(f.status.upper(), status_color, bold=True)}  "
            f"[{style(f.severity, sev_color)}]  "
            f"{style(f.setting, Color.MAGENTA, bold=True)}  "
            f"observed={f.observed!r}  expected={f.expected!r}"
        )

    # Give the operator an exit-code hint based on vulnerability count.
    print()
    if report.vulnerable_count == 0 and report.error_count == 0:
        success("Host appears compliant with the configured baseline.")
    else:
        warning(
            f"{report.vulnerable_count} setting(s) deviate from baseline - "
            f"review the report and apply remediations."
        )


__all__ = [
    "Finding",
    "AuditReport",
    "SysctlAuditor",
    "SSHAuditor",
    "run_defensive",
    "write_report",
    "print_report",
]
