"""Centralized configuration and security baselines.

All recommended values are inspired by widely accepted hardening
benchmarks (CIS, NIST, vendor defaults). They are intentionally
opinionated defaults that you can override when integrating this tool
into a customer-specific compliance policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple, Union

# ----------------------------------------------------------------------
# Filesystem paths
# ----------------------------------------------------------------------

# Standard Linux paths used by the defensive auditor.
SSHD_CONFIG_DEFAULT = "/etc/ssh/sshd_config"
SYSCTL_PROC_ROOT = Path("/proc/sys")

# ----------------------------------------------------------------------
# Kernel (sysctl) baseline
# ----------------------------------------------------------------------

# Each entry: (human label, expected secure value(s))
# ``True``/``False`` represent boolean sysctl toggles.
# Integer values represent numeric toggles.
# A tuple of acceptable values means "any of these is considered safe".
KERNEL_BASELINE: Dict[str, Tuple[int, ...]] = {
    # IP forwarding should be disabled on end hosts.
    "net.ipv4.ip_forward": (0,),
    # Source routing must be off.
    "net.ipv4.conf.all.accept_source_route": (0,),
    "net.ipv4.conf.default.accept_source_route": (0,),
    # ICMP redirects should be ignored (rare exceptions for routers).
    "net.ipv4.conf.all.accept_redirects": (0,),
    "net.ipv4.conf.default.accept_redirects": (0,),
    "net.ipv4.conf.all.secure_redirects": (0,),
    "net.ipv4.conf.default.secure_redirects": (0,),
    "net.ipv4.conf.all.send_redirects": (0,),
    # Reverse-path filtering mitigates spoofed packets.
    "net.ipv4.conf.all.rp_filter": (1,),
    "net.ipv4.conf.default.rp_filter": (1,),
    # SYN cookies protect against SYN-flood DoS.
    "net.ipv4.tcp_syncookies": (1,),
    # Ignore smurf-style broadcast pings.
    "net.ipv4.icmp_echo_ignore_broadcasts": (1,),
    # Log suspicious packets (martians).
    "net.ipv4.conf.all.log_martians": (1,),
}


# ----------------------------------------------------------------------
# SSH server baseline
# ----------------------------------------------------------------------

# Value-side of SSH baselines can be either:
# * a tuple of allowed strings (e.g. ``("no", "prohibit-password")``)
# * a frozenset of allowed stringified integers (e.g. acceptable seconds)
SafeValues = Union[Tuple[str, ...], FrozenSet[str]]

# Each tuple: (allowed safe values, severity if violated, description).
# Empty string == directive not present (treated as default).
SSHD_BASELINE: Dict[str, Tuple[SafeValues, str, str]] = {
    "Protocol": (
        ("2",),
        "high",
        "SSH must operate in Protocol 2 only (Protocol 1 is deprecated and insecure).",
    ),
    "PermitRootLogin": (
        ("no", "prohibit-password", "without-password"),
        "high",
        "Root login over SSH must be disabled (set to 'no' or prohibit-password).",
    ),
    "PasswordAuthentication": (
        ("no",),
        "high",
        "PasswordAuthentication should be 'no' - prefer key-based auth.",
    ),
    "PermitEmptyPasswords": (
        ("no",),
        "critical",
        "PermitEmptyPasswords MUST be 'no' - empty passwords are trivially exploitable.",
    ),
    "ChallengeResponseAuthentication": (
        ("no",),
        "medium",
        "ChallengeResponseAuthentication should be 'no' to avoid PAM bypasses.",
    ),
    "UsePAM": (
        ("yes",),
        "medium",
        "UsePAM is recommended 'yes' for centralized account/policy management.",
    ),
    "X11Forwarding": (
        ("no",),
        "low",
        "X11Forwarding should be 'no' unless strictly required.",
    ),
    "MaxAuthTries": (
        ("3", "2", "1"),
        "medium",
        "MaxAuthTries should be <= 3 to slow down brute-force attempts.",
    ),
    "ClientAliveInterval": (
        # Frozen interval range so look-ups are O(1) and humans can read it
        # without staring at an 841-element literal.
        frozenset(str(i) for i in range(60, 901)),
        "low",
        "ClientAliveInterval should be set (60-900s) to detect stale sessions.",
    ),
    "ClientAliveCountMax": (
        ("0", "1", "2", "3"),
        "low",
        "ClientAliveCountMax should be low (0-3) so dead clients are dropped quickly.",
    ),
    "PermitUserEnvironment": (
        ("no",),
        "medium",
        "PermitUserEnvironment must be 'no' to prevent attacker-controlled env vars.",
    ),
    "AllowTcpForwarding": (
        ("no",),
        "low",
        "AllowTcpForwarding should be restricted unless needed.",
    ),
    "IgnoreRhosts": (
        ("yes",),
        "medium",
        "IgnoreRhosts must be 'yes' (.rhosts shosts are insecure).",
    ),
    "HostbasedAuthentication": (
        ("no",),
        "medium",
        "HostbasedAuthentication should be 'no' on host-hardened systems.",
    ),
}


# ----------------------------------------------------------------------
# Severity scale (used by report renderer)
# ----------------------------------------------------------------------

SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "info"]


class ModuleStatus(str, Enum):
    """Audit / scan result status taxonomy."""

    SAFE = "safe"
    VULNERABLE = "vulnerable"
    ERROR = "error"
    INFO = "info"


@dataclass(frozen=True)
class OffCliDefaults:
    """Tunable defaults for the offensive CLI subcommand."""

    nmap_binary: str = "nmap"
    searchsploit_binary: str = "searchsploit"
    timeout_seconds: int = 600
    default_ports: str = "1-1024"
    # nmap flags: service & version detection + open ports + XML output.
    nmap_flags: Tuple[str, ...] = (
        "-sV",          # Probe open ports to determine service/version info.
        "-sC",          # Run default scripts (banner grabbing, vuln discovery hints).
        "-Pn",          # Treat host as online (offensive tools often target isolated nets).
        "--open",        # Show only open ports.
        "-T4",          # Aggressive (but sane) timing template.
    )


@dataclass(frozen=True)
class DefCliDefaults:
    """Tunable defaults for the defensive CLI subcommand."""

    sshd_config_path: str = SSHD_CONFIG_DEFAULT
    report_path: str = "cyberguard_defensive_report.txt"


__all__ = [
    "SSHD_CONFIG_DEFAULT",
    "SYSCTL_PROC_ROOT",
    "KERNEL_BASELINE",
    "SSHD_BASELINE",
    "SafeValues",
    "SEVERITY_ORDER",
    "ModuleStatus",
    "OffCliDefaults",
    "DefCliDefaults",
]
