# CyberGuard

> **A modular CLI security toolkit in Python.**
> Combines an *offensive* scan/automation module (eJPT-style) with a
> *defensive* SOC/hardening auditor behind a single, clean CLI.

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![license](https://img.shields.io/badge/license-MIT-green)](#license)
[![deps](https://img.shields.io/badge/runtime%20deps-zero-brightgreen)](#dependencies)

---

## ✨ Features

### 1. Offensive module — `nmap + searchsploit` automation
- Runs **Nmap** with service/version detection (`-sV -sC`).
- Saves an **XML** archive of every scan for later re-parsing.
- Programmatically extracts each `(host, port, protocol, service, version)` tuple.
- Feeds the service banner straight into **searchsploit** to surface
  known public exploits from your **local** Exploit-DB archive.
- Returns a structured `ScanReport` plus a colourised summary.

### 2. Defensive module — host hardening auditor
- **Read-only** audit of `/proc/sys/...` sysctl values against a CIS-style baseline.
- Parses `sshd_config` against an opinionated hardening baseline
  (`PermitRootLogin`, `PasswordAuthentication`, `MaxAuthTries`, …).
- Produces a colourised stdout summary **and** an optional plain-text
  report.
- Exit codes are CI/CD-friendly: `0` clean, `1` vulnerable, `2` partial error.

### 3. Architecture highlights
- **Zero runtime dependencies** — runs on a stock Python 3.9+ install.
- Modular package layout (`offensive.py`, `defensive.py`, `utils.py`),
  designed so additional modules (web, wireless, reporting, …) can be
  plugged in next to the existing two.
- `argparse`-based CLI with sub-commands (`offensive`, `defensive`).
- `dataclass`-based result objects — easy to consume from notebooks or
  web dashboards.
- Defensive auditor never mutates system state.

---

## 📁 Project layout

```
frebuff/
├── cyberguard/
│   ├── __init__.py            # Package metadata
│   ├── __main__.py            # Allows `python -m cyberguard`
│   ├── cli.py                 # argparse CLI entry point
│   ├── config.py              # Hardening baselines & defaults
│   ├── defensive.py           # sysctl + sshd_config auditor
│   ├── offensive.py           # nmap + searchsploit pipeline
│   └── utils.py               # Colours, subprocess helpers, XML parsing
├── main.py                    # Convenience shim → `python main.py …`
├── requirements.txt           # Intentionally empty (zero deps)
├── README.md                  # ← you are here
└── .gitignore
```

---

## ⚙️ Installation

```bash
# 1. Clone
git clone https://github.com/<your-org>/cyberguard.git
cd cyberguard

# 2. (Optional but recommended) create and activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the external tools the modules call into
#    - nmap        : https://nmap.org/download.html
#    - searchsploit: ships with exploit-db (`sudo apt install exploitdb`)
```

> Everything inside `requirements.txt` is commentary; the project runs
> with **only** the Python standard library. Uncomment `rich` /
> `colorama` if you want richer terminal output.

---

## 🚀 Usage

### Show the help

```bash
python main.py --help
python main.py offensive --help
python main.py defensive --help
```

### Offensive module

```bash
# Default scan: top 1024 ports, sV + sC nmap scripts, searchsploit feed.
python main.py offensive --target scanme.nmap.org

# Custom port list and output directory.
python main.py offensive -t 192.0.2.10 -p 22,80,443 -o ./scans

# Full-range TCP scan, no searchsploit feed.
python main.py offensive -t 10.0.0.5 -p 1-65535 --no-searchsploit
```

The command writes a timestamped XML file to the output directory, then
prints a colourised table of discovered services and any matching
exploit-DB entries.

### Defensive module

```bash
# Audit the local host (sysctl + /etc/ssh/sshd_config).
python main.py defensive

# Custom sshd_config path and persist the full report.
python main.py defensive \
    --sshd-config /etc/ssh/sshd_config \
    --report ./cyberguard_defensive_report.txt
```

Sample output (truncated):

```
=================================================================
                Defensive Audit Report
=================================================================
  Compliant: 9  Vulnerable: 4  Error: 1  Total: 14

[sysctl]
  SAFE       [info]  net.ipv4.ip_forward  observed='0'  expected='0'
  VULNERABLE [medium]  net.ipv4.icmp_echo_ignore_broadcasts  observed='0'  expected='1'
...

[sshd]
  SAFE       [info]  PermitRootLogin  observed='prohibit-password'  expected='no/prohibit-password/without-password'
  VULNERABLE [critical]  PermitEmptyPasswords  observed='yes'  expected='no'
```

Exit codes (useful for CI/CD pipelines):

### `defensive` subcommand

Precedence: **error > vulnerable > clean** - the auditor prefers to
report "partially failed" over "looks clean" when it could not collect
enough evidence.

| Code | Meaning                          |
|------|----------------------------------|
| 0    | Fully compliant                  |
| 1    | At least one vulnerable setting  |
| 2    | Read error / partial audit       |
| 64   | Usage error (e.g. bad CLI flags) |
| 130  | Interrupted by the user          |

### `offensive` subcommand

| Code | Meaning                                                    |
|------|------------------------------------------------------------|
| 0    | Scan completed, ≥ 1 open service found                      |
| 1    | Scan completed, no open services surfaced                   |
| 64   | Usage error (e.g. empty `--ports`)                          |
| 130  | Interrupted by the user                                    |

---

## 🧩 Extending CyberGuard

Add a new module by following the same shape as `offensive.py` /
`defensive.py`:

1. Create `cyberguard/<module>.py` exporting a `run_<module>()` function
   (or class) returning a dataclass.
2. Register the new sub-parser in `cyberguard/cli.py:build_parser`.
3. Add any constraints to `requirements.txt`.
4. Document it in this README.

---

## ⚠️ Legal disclaimer

CyberGuard ships with powerful offensive-assistance primitives. You are
**solely responsible** for ensuring you have explicit, written
authorization before scanning any system that is not your own. The
authors disclaim all liability for misuse.

---

## 🔧 API stability / migration notes

If you embed CyberGuard as a library (not just the CLI), a few public
symbols changed between releases:

- ``cyberguard.utils.parse_nmap_xml`` now returns
  ``Tuple[List[NmapService], List[NmapScriptHit]]`` (services + NSE
  script findings) instead of ``List[NmapService]``. Iterating over the
  return value directly will iterate the *tuple*. Unpack explicitly:
  ``services, scripts = parse_nmap_xml(path)``.
- ``cyberguard.offensive.ScanReport`` gained ``scripts`` and
  ``service_exploits`` fields; existing keyword arguments remain valid
  because both use ``default_factory``.
- ``cyberguard.run_offensive`` gained an ``enable_searchsploit`` kwarg
  (``True`` by default) - set to ``False`` to skip the searchsploit feed
  in CI runs.

The CLI surface is unchanged across releases.

---

## 📜 License

Released under the **MIT License**. See `LICENSE` (add your own copy in
your fork) for details.
