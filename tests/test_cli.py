import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from email_audit import cli
from email_audit.output.console import print_assessment
from email_audit.output.evidence import report_configuration_validation


class CliTests(unittest.TestCase):
    def test_help_shows_existing_options_and_examples(self):
        result = subprocess.run(
            [sys.executable, "-m", "email_audit.cli", "--help"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--email", result.stdout)
        self.assertIn("--spoof", result.stdout)
        self.assertIn("--csacyber", result.stdout)
        self.assertIn("email-audit example.com", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_assessment_and_evidence_preserve_literal_dns_text(self):
        result = {
            "control": "SPF",
            "raw": "v=spf1 [test] -all",
            "breakdown": ["[test]"],
            "impact": "Example impact",
            "assessment": "SECURE",
        }
        dkim = {
            "control": "DKIM",
            "breakdown": ["Selector extracted from supplied email: [test]"],
            "assessment": "PRESENT",
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_assessment(result)
            report_configuration_validation([
                result, dkim,
                {"control": "DMARC", "tags": {"p": "reject"}, "assessment": "SECURE"},
                {"control": "MTA-STS", "policy": {"mode": "enforce"}, "assessment": "SECURE"},
            ])
        self.assertIn("v=spf1 [test] -all", output.getvalue())
        self.assertIn("[test]", output.getvalue())
        self.assertIn("[SPF]", output.getvalue())
        self.assertNotIn("Security Impact:", output.getvalue())
        self.assertNotIn("Assessment:", output.getvalue())
        self.assertNotIn("\x1b[", output.getvalue())

    def test_inconclusive_check_displays_explanation(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_assessment({
                "control": "TLS-RPT", "raw": "", "breakdown": ["DNS lookup failed: timeout"],
                "assessment": "UNKNOWN",
                "impact": "TLS reporting configuration could not be determined.",
            })
        self.assertIn("DNS lookup failed: timeout", output.getvalue())
        self.assertIn("TLS reporting configuration could not be determined.", output.getvalue())
        self.assertNotIn("Assessment:", output.getvalue())

    def test_sample_workflow_exports_findings_and_html(self):
        with contextlib.ExitStack() as cleanup:
            directory = cleanup.enter_context(tempfile.TemporaryDirectory())
            old_cwd = os.getcwd()
            cleanup.callback(os.chdir, old_cwd)
            os.chdir(directory)
            with open("sample.eml", "w", encoding="utf-8") as sample:
                sample.write(
                    "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
                    "DKIM-Signature: v=1; d=example.test; s=sample;\n\n"
                )
            output = io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch("sys.argv", [
                    "email-audit", "example.test", "--email", "sample.eml"
                ]))
                clock = stack.enter_context(patch.object(cli, "datetime"))
                clock.now.side_effect = [
                    datetime(2026, 1, 2, 3, 4, 5, 1),
                    datetime(2026, 1, 2, 3, 4, 5, 2),
                ]
                stack.enter_context(patch.object(cli, "get_spf_record", return_value="v=spf1 -all"))
                dkim = stack.enter_context(patch.object(
                    cli, "check_dkim_dns", return_value=("sample", "v=DKIM1; p=key", True)
                ))
                stack.enter_context(patch.object(
                    cli, "check_dkim_selectors", return_value=[("sample", "v=DKIM1; p=key", True)]
                ))
                stack.enter_context(patch.object(cli, "get_dmarc_record", return_value="v=DMARC1; p=reject"))
                stack.enter_context(patch.object(cli, "check_mta_sts", return_value="v=STSv1; id=1"))
                stack.enter_context(patch.object(
                    cli, "get_tls_rpt_records",
                    return_value=(["v=TLSRPTv1; rua=mailto:a@example.test"], None),
                ))
                stack.enter_context(patch.object(
                    cli, "get_mta_sts_policy", return_value="version: STSv1\nmode: enforce"
                ))
                progress = stack.enter_context(patch.object(cli, "Progress"))
                stack.enter_context(contextlib.redirect_stdout(output))
                cli.main()
                cli.main()
            dkim.assert_any_call("example.test", "sample")
            tracker = progress.return_value.__enter__.return_value
            self.assertEqual(tracker.update.call_count, 10)
            self.assertEqual(tracker.update.call_args.kwargs["description"], "DNS checks complete")
            prefix = Path("email-audit") / "example.test-20260102-030405-000001"
            second_prefix = Path("email-audit") / "example.test-20260102-030405-000002"
            with open(f"{prefix}.json", encoding="utf-8") as findings_file:
                findings = json.load(findings_file)
            self.assertEqual(findings["domain"], "example.test")
            self.assertEqual(findings["findings"][0]["id"], "email-audit")
            with open(f"{prefix}.html", encoding="utf-8") as report_file:
                report = report_file.read()
            self.assertTrue(Path(f"{second_prefix}.json").is_file())
            self.assertTrue(Path(f"{second_prefix}.html").is_file())
            self.assertIn("<h2>Executive Summary</h2>", report)
            self.assertIn("<h2>Technical Commentary</h2>", report)
            self.assertIn("<h2>Recommendations</h2>", report)
            self.assertNotIn("<h2>Findings</h2>", report)
            self.assertIn("Authentication", output.getvalue())
            self.assertIn("PASS", output.getvalue())
            self.assertIn("Assessment Complete", output.getvalue())
            self.assertIn(f"{prefix}.json", output.getvalue())
            self.assertIn(f"{prefix}.html", output.getvalue())
            self.assertTrue(output.getvalue().startswith("\n"))
            self.assertNotIn("Overall Security Posture", output.getvalue())

    def test_csacyber_writes_xml_and_html_instead_of_json(self):
        with contextlib.ExitStack() as stack:
            directory = stack.enter_context(tempfile.TemporaryDirectory())
            old_cwd = os.getcwd()
            stack.callback(os.chdir, old_cwd)
            os.chdir(directory)
            stack.enter_context(patch("sys.argv", ["email-audit", "example.test", "--csacyber"]))
            stack.enter_context(patch.object(cli, "get_spf_record", return_value=""))
            stack.enter_context(patch.object(cli, "check_dkim_selectors", return_value=[]))
            stack.enter_context(patch.object(cli, "get_dmarc_record", return_value=""))
            stack.enter_context(patch.object(cli, "check_mta_sts", return_value=""))
            stack.enter_context(patch.object(cli, "get_mta_sts_policy", return_value=""))
            stack.enter_context(patch.object(cli, "get_tls_rpt_records", return_value=([], None)))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

            cli.main()

            html_files = list(Path("email-audit").glob("example.test-*.html"))
            xml_files = list(Path("email-audit").glob("example.test-*.xml"))
            self.assertEqual(len(html_files), 1)
            self.assertEqual(len(xml_files), 1)
            self.assertEqual(html_files[0].stem, xml_files[0].stem)
            self.assertFalse(list(Path("email-audit").glob("*.json")))
            root = ET.parse(xml_files[0]).getroot()
            ids = [node.get("id") for node in root.findall(".//vulnerability")]
            self.assertEqual(ids, ["SC-2157", "SC-2090", "SC-2165", "SC-2166", "SC-6842", "SC-6840"])
            self.assertIn("XML Output", output.getvalue())
            self.assertIn("HTML Output", output.getvalue())

    def test_terminal_progress_shows_each_check(self):
        terminal = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("sys.argv", ["email-audit", "example.test"]))
            stack.enter_context(patch.object(cli.Path, "mkdir"))
            stack.enter_context(patch.object(cli, "console", Console(file=terminal, force_terminal=True)))
            for name in (
                "get_spf_record", "get_dmarc_record", "check_mta_sts",
                "get_mta_sts_policy", "parse_mta_sts_policy", "assess_spf",
                "assess_dkim_records", "assess_dmarc", "assess_mta_sts",
                "print_info", "print_assessment", "build_findings",
                "build_commentary", "build_recommendations", "export_json", "export_html",
                "print_completion_summary",
            ):
                stack.enter_context(patch.object(cli, name))
            stack.enter_context(patch.object(cli, "check_dkim_selectors", return_value=[]))
            stack.enter_context(patch.object(cli, "get_tls_rpt_records", return_value=([], None)))
            cli.main()
        for label in ("SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT", "DNS checks complete"):
            self.assertIn(label, terminal.getvalue())
        self.assertIn("5/5", terminal.getvalue())


if __name__ == "__main__":
    unittest.main()
