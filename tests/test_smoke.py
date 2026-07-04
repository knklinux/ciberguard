"""Smoke tests exercising the user-visible behavior of every parser.

Run with::

    python -m unittest tests.test_smoke -v

The tests don't require nmap / searchsploit / root - they exercise the
unparsered layer (XML parsing, sshd_config parsing, searchsploit JSON
decoding) plus the steady-state behaviors of the orchestrators.
"""

from __future__ import annotations

import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import List

from cyberguard import cli, config, defensive, offensive, utils  # noqa: F401
from cyberguard.utils import parse_nmap_xml, parse_searchsploit_json


NMAP_XML = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sV 127.0.0.1"
             start="1" version="7.94" xmloutputversion="1.04">
      <host>
        <status state="up"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9p1"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="closed"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="http" product="nginx" version="1.21.0"/>
            <script id="ssl-cert" output="Subject: example.com"/>
          </port>
          <!-- garbage portid should be skipped, not emitted as port=0 -->
          <port protocol="tcp" portid="not-a-number">
            <state state="open"/>
            <service name="ignored"/>
          </port>
        </ports>
        <hostscript>
          <script id="smb-vuln-ms17-010" output="VULNERABLE"/>
        </hostscript>
      </host>
      <runstats>
        <finished time="2" elapsed="1" summary="OK" exit="success"/>
      </runstats>
    </nmaprun>
    """
)


SSHD_GOOD = textwrap.dedent(
    """\
    # Full hardened baseline covering every SSHD_BASELINE directive.
    Protocol 2
    PermitRootLogin prohibit-password
    PasswordAuthentication no
    PermitEmptyPasswords no
    ChallengeResponseAuthentication no
    UsePAM yes
    X11Forwarding no
    MaxAuthTries 3
    ClientAliveInterval 300
    ClientAliveCountMax 2
    PermitUserEnvironment no
    AllowTcpForwarding no
    IgnoreRhosts yes
    HostbasedAuthentication no
    """
)


SSHD_WITH_MATCH = SSHD_GOOD + textwrap.dedent(
    """\
    Match Group sftpusers
        ForceCommand internal-sftp
        ChrootDirectory /home
    """
)


SEARCHSPLOIT_JSON = json.dumps(
    {
        "SEARCHSPLOIT": {"DB_FILES": {"LINUX": 1}},
        "RESULTS_EXPLOIT": [
            {
                "Title": "OpenSSH 8.9 - Auth Bypass",
                "Path": "exploits/linux/remote/12345.py",
                "Type": "python",
                "Platform": "linux",
            },
            {
                "Title": "OpenSSH 8.9 Privilege Escalation",
                "Path": "exploits/linux/local/67890.sh",
                "Type": "shellcode",
                "Platform": "linux",
            },
        ],
        "RESULTS_SHELLCODE": [],
    }
)


class TestNmapXmlParser(unittest.TestCase):
    """The XML parser must surface open services *and* -sC script hits."""

    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False
        )
        self.tmp.write(NMAP_XML)
        self.tmp.close()

    def tearDown(self) -> None:
        os.unlink(self.tmp.name)

    def test_returns_services_and_scripts(self) -> None:
        services, scripts = parse_nmap_xml(self.tmp.name)
        # 3 open services: 22 + 443, plus port=??? is dropped, 80 is closed.
        self.assertEqual(len(services), 2)
        ports = {(s.port, s.protocol) for s in services}
        self.assertEqual(ports, {(22, "tcp"), (443, "tcp")})

    def test_service_fields_parsed(self) -> None:
        services, _ = parse_nmap_xml(self.tmp.name)
        ssh = next(s for s in services if s.port == 22)
        self.assertEqual(ssh.name, "ssh")
        self.assertEqual(ssh.product, "OpenSSH")
        self.assertEqual(ssh.version, "8.9p1")
        self.assertEqual(ssh.banner, "ssh OpenSSH 8.9p1")

    def test_script_hits_present(self) -> None:
        _, scripts = parse_nmap_xml(self.tmp.name)
        ids = {s.script_id for s in scripts}
        # ssl-cert is port-scoped; smb-vuln-ms17-010 is host-level.
        self.assertIn("ssl-cert", ids)
        self.assertIn("smb-vuln-ms17-010", ids)

    def test_port_scripts_carry_port(self) -> None:
        _, scripts = parse_nmap_xml(self.tmp.name)
        ssl = next(s for s in scripts if s.script_id == "ssl-cert")
        self.assertEqual(ssl.port, 443)
        host_script = next(s for s in scripts if s.script_id == "smb-vuln-ms17-010")
        self.assertIsNone(host_script.port)

    def test_closed_port_is_skipped_for_service(self) -> None:
        services, _ = parse_nmap_xml(self.tmp.name)
        ports = {s.port for s in services}
        self.assertNotIn(80, ports)


class TestSearchsploitJsonDecoder(unittest.TestCase):
    def test_parses_modern_json_shape(self) -> None:
        result = parse_searchsploit_json(SEARCHSPLOIT_JSON)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["title"], "OpenSSH 8.9 - Auth Bypass")
        self.assertTrue(result[0]["path"].endswith("12345.py"))

    def test_returns_none_on_garbage(self) -> None:
        self.assertIsNone(parse_searchsploit_json("not really json"))
        self.assertIsNone(parse_searchsploit_json(""))
        self.assertIsNone(parse_searchsploit_json(json.dumps({"foo": "bar"})))

    def test_skips_rows_missing_keys(self) -> None:
        payload = json.dumps(
            {"RESULTS_EXPLOIT": [{"Title": "", "Path": "/x"}]}
        )
        self.assertEqual(parse_searchsploit_json(payload), [])


class TestSearchsploitSearcher(unittest.TestCase):
    def test_json_path_builds_hits(self) -> None:
        # Patch ``offensive.run_command`` (the bound name inside the
        # offensive module) - ``utils.run_command`` is the original source
        # but the module-level import has already rebound it locally.
        from cyberguard.offensive import SearchsploitSearcher

        captured: List[List[str]] = []

        def fake_run(cmd, timeout=None, check=False, input_text=None):
            captured.append(list(cmd))
            return utils.CommandResult(0, SEARCHSPLOIT_JSON, "", list(cmd))

        original = offensive.run_command
        offensive.run_command = fake_run  # type: ignore[assignment]
        try:
            searcher = SearchsploitSearcher()
            hits = searcher.query("OpenSSH 8.9")
        finally:
            offensive.run_command = original  # type: ignore[assignment]

        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0].title, "OpenSSH 8.9 - Auth Bypass")
        # ``--format json`` was appended to the command line.
        self.assertIn("--format", captured[0])
        self.assertIn("json", captured[0])

    def test_legacy_fallback_when_json_invalid(self) -> None:
        from cyberguard.offensive import SearchsploitSearcher

        # JSON parse fails → a second invocation produces the legacy
        # table-format output. Both must be parsed and the header +
        # separator rows must be skipped (this guards against the
        # regression where the header regex matched too narrowly).
        calls = {"n": 0}

        legacy_text = (
            "-------------------------------------------------------------------------- ---------------------------------\n"
            "  Exploit Title                                                              | Path\n"
            "                                                                          ( | Description)\n"
            "-------------------------------------------------------------------------- ---------------------------------\n"
            "  Apache httpd 2.4.52 - mod_proxy SSRF                                       | exploits/linux/web/12345.py\n"
        )

        def fake_run(cmd, timeout=None, check=False, input_text=None):
            calls["n"] += 1
            if calls["n"] == 1:
                # First invocation: --format json, returns invalid JSON.
                return utils.CommandResult(0, "this is not json", "", list(cmd))
            return utils.CommandResult(0, legacy_text, "", list(cmd))

        original = offensive.run_command
        offensive.run_command = fake_run  # type: ignore[assignment]
        try:
            hits = SearchsploitSearcher().query("Apache httpd")
        finally:
            offensive.run_command = original  # type: ignore[assignment]

        self.assertEqual(calls["n"], 2)
        self.assertEqual(len(hits), 1, f"unexpected hits: {[h.title for h in hits]}")
        self.assertEqual(hits[0].title, "Apache httpd 2.4.52 - mod_proxy SSRF")


class TestSSHAuditor(unittest.TestCase):
    def _auditor(self, content: str) -> defensive.SSHAuditor:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix="_sshd_config", delete=False
        )
        tmp.write(content)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return defensive.SSHAuditor(tmp.name)

    def test_parses_first_match_only(self) -> None:
        auditor = self._auditor(SSHD_GOOD)
        directives, saw_match = auditor.parse()
        self.assertFalse(saw_match)
        self.assertEqual(directives["Protocol"], "2")
        self.assertEqual(directives["PermitRootLogin"], "prohibit-password")

    def test_match_block_truncates_global_map(self) -> None:
        auditor = self._auditor(SSHD_WITH_MATCH)
        directives, saw_match = auditor.parse()
        self.assertTrue(saw_match)
        # ForceCommand / ChrootDirectory appear only inside the Match
        # block and must NOT leak into the global directives map.
        self.assertNotIn("ForceCommand", directives)
        self.assertNotIn("ChrootDirectory", directives)
        # Globals above Match still parse correctly.
        self.assertEqual(directives["PermitRootLogin"], "prohibit-password")

    def test_audit_flags_unsafe_directives(self) -> None:
        bad = SSHD_GOOD.replace("PermitRootLogin prohibit-password", "PermitRootLogin yes")
        bad = bad.replace("PasswordAuthentication no", "PasswordAuthentication yes")
        findings = self._auditor(bad).audit()
        settings = {f.setting: f for f in findings if f.setting in {
            "PermitRootLogin", "PasswordAuthentication"
        }}
        self.assertEqual(settings["PermitRootLogin"].status, "vulnerable")
        self.assertEqual(settings["PasswordAuthentication"].status, "vulnerable")

    def test_match_block_emits_info_finding(self) -> None:
        findings = self._auditor(SSHD_WITH_MATCH).audit()
        match_finding = next(
            f for f in findings if f.setting == "<Match blocks>"
        )
        self.assertEqual(match_finding.status, "info")
        self.assertEqual(match_finding.severity, "low")

    def test_missing_file_is_error(self) -> None:
        findings = defensive.SSHAuditor("/nonexistent/sshd_config").audit()
        self.assertEqual(findings[0].status, "error")
        self.assertIn("not found", findings[0].description)


class TestOffensiveOrchestration(unittest.TestCase):
    def test_enable_searchsploit_false_skips_searcher(self) -> None:
        # All we care about: searcher must never be invoked and the
        # `require_tool` gate is bypassed.
        from cyberguard.offensive import NmapScanner

        # Faked scanner writes a valid XML; emulate /bin/true for nmap.
        fake_xml = NMAP_XML.encode()

        class _FakeRaw:
            returncode = 0
            stdout = ""
            stderr = ""

        tmp_xml = tempfile.NamedTemporaryFile(
            mode="wb", suffix=".xml", delete=False
        )
        tmp_xml.write(fake_xml)
        tmp_xml.close()
        self.addCleanup(os.unlink, tmp_xml.name)

        class FakeScanner(NmapScanner):
            def scan(self, target, *, ports, output_dir, file_stem=None):
                # Re-use the temp file we already wrote.
                return Path(tmp_xml.name), utils.CommandResult(
                    0, "", "", ["nmap", "-p", ports]
                )

        # ``searcher=`` is irrelevant when enable_searchsploit=False;
        # even if it is non-None, the orchestrator must skip query().
        searcher_calls = {"n": 0}

        class _SentinelSearcher:
            binary = "sentinel"

            def query(self, _b):
                searcher_calls["n"] += 1
                return []

        report = offensive.run_offensive(
            target="127.0.0.1",
            ports="22",
            output_dir=tempfile.gettempdir(),
            scanner=FakeScanner(),
            searcher=_SentinelSearcher(),  # type: ignore[arg-type]
            enable_searchsploit=False,
            verbose=False,
        )

        self.assertEqual(searcher_calls["n"], 0)
        self.assertEqual(report.exploits, [])
        # NSE scripts were still parsed.
        self.assertGreaterEqual(len(report.scripts), 1)
        # service_exploits is empty, but the field exists.
        self.assertEqual(report.service_exploits, {})


class TestDefensiveExitCodes(unittest.TestCase):
    def test_clean_host_yields_zero(self) -> None:
        # Pretend every sysctl value matches the baseline.
        from unittest.mock import patch

        class _AlwaysSafeSysctl(defensive.SysctlAuditor):
            def read_value(self, key):
                # Pretend every key returns its first safe value.
                from cyberguard.config import KERNEL_BASELINE
                expected = KERNEL_BASELINE[key]
                return str(expected[0])

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix="_sshd", delete=False
        )
        tmp.write(SSHD_GOOD)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)

        # ``patch.object`` auto-restores defensively even if the test
        # body raises - so the patched class cannot leak into other tests
        # sharing the same interpreter process.
        with patch.object(defensive, "SysctlAuditor", _AlwaysSafeSysctl):
            report = defensive.run_defensive(sshd_config_path=tmp.name)

        # All sysctl entries → safe; sshd (good baseline) → safe.
        self.assertEqual(report.vulnerable_count, 0)


class TestCliEntrypoint(unittest.TestCase):
    def test_top_level_help(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            cli.main(["--help"])
        self.assertEqual(exc.exception.code, 0)

    def test_offensive_help(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            cli.main(["offensive", "--help"])
        self.assertEqual(exc.exception.code, 0)

    def test_defensive_help(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            cli.main(["defensive", "--help"])
        self.assertEqual(exc.exception.code, 0)


class TestPackageEntryPoints(unittest.TestCase):
    """Smoke-tests for both shipping entry points.

    ``python -m cyberguard`` shells out to ``cyberguard/__main__.py``;
    ``python main.py`` shells out to ``cyberguard.cli.main``.
    Importing each catches accidental import regressions that the CLI
    help tests do not exercise directly.
    """

    def test_main_module_exposes_cli_main(self) -> None:
        import importlib

        mod = importlib.import_module("cyberguard.__main__")
        self.assertTrue(callable(getattr(mod, "main", None)))

    def test_main_py_shim_invokes_cli_main(self) -> None:
        # Static check - confirm main.py still delegates to cli.main.
        text = (Path(__file__).resolve().parent.parent / "main.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("from cyberguard.cli import main", text)
        self.assertIn("sys.exit(main())", text)


if __name__ == "__main__":
    unittest.main()
