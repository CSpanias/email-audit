import contextlib
import io
import json
import os
import smtplib
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from email_audit import cli
from email_audit.dns.dkim import assess_dkim
from email_audit.dns.dmarc import assess_dmarc
from email_audit.dns.mta_sts import assess_mta_sts, parse_mta_sts_policy
from email_audit.dns.spf import assess_spf
from email_audit.dns.tls_rpt import assess_tls_rpt
from email_audit.output.console import print_assessment, print_completion_summary
from email_audit.output.evidence import report_configuration_validation
from email_audit.spoofing import spoof


class CliTests(unittest.TestCase):
    def test_completion_summary_aligns_labels_for_both_export_formats(self):
        for output_format in ("JSON", "XML"):
            with self.subTest(output_format=output_format):
                output = io.StringIO()
                with patch("email_audit.output.console.console", Console(file=output, width=120)):
                    print_completion_summary(
                        [], "email-audit/example.findings", "email-audit/example.html",
                        output_format=output_format, exported_count=5,
                    )
                lines = [line for line in output.getvalue().splitlines() if " : " in line]
                self.assertEqual(len(lines), 3)
                self.assertEqual(len({line.index(" : ") for line in lines}), 1)
                self.assertIn(f"{output_format} Output", lines[1])

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
        self.assertIn("-D", result.stdout)
        self.assertIn("--domain", result.stdout)
        self.assertIn("email-audit -D example.com", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_domain_flag_is_required_and_both_forms_work(self):
        for flag in ("-D", "--domain"):
            with self.subTest(flag=flag), patch(
                "sys.argv", ["email-audit", flag, "example.test"]
            ):
                self.assertEqual(cli.parse_arguments().domain, "example.test")
        for arguments in ([], ["example.test"]):
            with self.subTest(arguments=arguments), patch(
                "sys.argv", ["email-audit", *arguments]
            ), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    cli.parse_arguments()
                self.assertEqual(exc.exception.code, 2)

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

    def test_dmarc_reduced_coverage_and_invalid_values_are_visible(self):
        for tags, expected in (
            ("p=reject; pct=0", "less restrictively"),
            ("p=reject; t=y", "less restrictively"),
            ("p=reject; pct=101", "Invalid DMARC pct value"),
        ):
            with self.subTest(tags=tags):
                output = io.StringIO()
                with patch("email_audit.output.console.console", Console(file=output, width=120)):
                    print_assessment(assess_dmarc(f"v=DMARC1; {tags}"))
                self.assertIn(expected, output.getvalue())

    def test_spf_fields_are_separate_and_explain_qualifiers(self):
        record = "v=spf1 include:mail.example.test ip4:192.0.2.0/24 ~all"
        output = io.StringIO()
        with patch("email_audit.output.console.console", Console(file=output, width=120)):
            print_assessment(assess_spf(record))
        lines = output.getvalue().splitlines()
        self.assertIn(record, output.getvalue())
        self.assertTrue(any(border in output.getvalue() for border in ("┏", "┌", "+")))
        self.assertTrue(any(border in output.getvalue() for border in ("┗", "└", "+")))
        self.assertTrue(any("v=spf1" in line and "SPF record version" in line for line in lines))
        self.assertTrue(any("include:mail.example.test" in line and "referenced" in line for line in lines))
        self.assertTrue(any("ip4:192.0.2.0/24" in line and "IPv4" in line for line in lines))
        self.assertTrue(any("~all" in line and "soft failure" in line for line in lines))

    def test_dkim_fields_keep_raw_split_record_and_key_observations(self):
        record = '"v=DKIM1; k=rsa; p=abc" "def"'
        output = io.StringIO()
        with patch("email_audit.output.console.console", Console(file=output, width=120)):
            print_assessment(assess_dkim("sample", record, True))
        text = output.getvalue()
        self.assertIn(record, text)
        self.assertIn("DKIM record version", text)
        self.assertIn("Public key algorithm", text)
        self.assertIn("p=<public key>", text)
        self.assertIn("Public key used to verify signatures", text)
        self.assertIn("Selector extracted from supplied email: sample", text)
        self.assertIn("DKIM RSA public key could not be decoded", text)

    def test_other_records_explain_fields_and_keep_invalid_diagnostics(self):
        results = [
            assess_dmarc("v=DMARC1; p=none; rua=mailto:a@example.test; custom=x"),
            assess_mta_sts('"v=STSv1; id=123"', parse_mta_sts_policy(
                "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 86400"
            )),
            assess_tls_rpt(["v=TLSRPTv1; rua=invalid"]),
        ]
        output = io.StringIO()
        with patch("email_audit.output.console.console", Console(file=output, width=120)):
            for result in results:
                print_assessment(result)
        text = output.getvalue()
        for expected in (
            "DMARC record version", "Monitor failures without requesting enforcement",
            "Destination for aggregate reports", "Unrecognised or unsupported field",
            "Policy identifier used to detect changes", "policy: mode=enforce",
            "Authorised mail server", "TLS reporting record version",
            "Destinations for email transport security reports", "missing or invalid reporting URI",
        ):
            self.assertIn(expected, text)

    def test_unparseable_quoted_dkim_record_is_not_silently_discarded(self):
        output = io.StringIO()
        result = assess_dkim("sample", '"v=DKIM1; p=broken', True)
        with patch("email_audit.output.console.console", Console(file=output, width=120)):
            print_assessment(result)
        self.assertIn('"v=DKIM1; p=broken', output.getvalue())
        self.assertIn("Could not parse the quoted record into fields", output.getvalue())

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
                    "email-audit", "-D", "example.test", "--email", "sample.eml"
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

    def test_dns_failures_remain_inconclusive_in_exported_report_and_findings(self):
        import dns.exception

        with contextlib.ExitStack() as stack:
            directory = stack.enter_context(tempfile.TemporaryDirectory())
            old_cwd = os.getcwd()
            stack.callback(os.chdir, old_cwd)
            os.chdir(directory)
            stack.enter_context(patch("sys.argv", ["email-audit", "-D", "example.test"]))
            stack.enter_context(patch(
                "email_audit.dns.lookup.dns.resolver.resolve",
                side_effect=dns.exception.Timeout("DNS timed out"),
            ))
            policy = stack.enter_context(patch.object(cli, "get_mta_sts_policy"))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

            cli.main()

            findings_path = next(Path("email-audit").glob("*.json"))
            report_path = next(Path("email-audit").glob("*.html"))
            with findings_path.open(encoding="utf-8") as handle:
                findings = json.load(handle)["findings"]
            report = report_path.read_text(encoding="utf-8")
            self.assertEqual([finding["id"] for finding in findings], ["email-audit"])
            self.assertIn("DNS lookup failed", output.getvalue())
            self.assertIn("DNS lookup failures", report)
            self.assertIn("DKIM support could not be confirmed", report)
            self.assertNotIn("No SPF record was identified", report)
            self.assertNotIn("No DMARC policy was identified", report)
            policy.assert_not_called()

    def test_csacyber_writes_xml_and_html_instead_of_json(self):
        with contextlib.ExitStack() as stack:
            directory = stack.enter_context(tempfile.TemporaryDirectory())
            old_cwd = os.getcwd()
            stack.callback(os.chdir, old_cwd)
            os.chdir(directory)
            stack.enter_context(patch("sys.argv", ["email-audit", "-D", "example.test", "--csacyber"]))
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
            stack.enter_context(patch("sys.argv", ["email-audit", "-D", "example.test"]))
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

    def test_skipped_spoof_test_never_prompts_for_delivery_or_reports_a_result(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("sys.argv", [
                "email-audit", "-D", "example.test", "--spoof", "recipient@example.test"
            ]))
            stack.enter_context(patch.object(cli.Path, "mkdir"))
            for name in (
                "get_spf_record", "get_dmarc_record", "check_mta_sts",
                "get_mta_sts_policy", "parse_mta_sts_policy", "assess_spf",
                "assess_dkim_records", "assess_dmarc", "assess_mta_sts",
                "print_info", "print_assessment", "build_recommendations",
                "export_json", "export_html", "print_completion_summary", "report_spoof",
            ):
                stack.enter_context(patch.object(cli, name))
            stack.enter_context(patch.object(cli, "check_dkim_selectors", return_value=[]))
            stack.enter_context(patch.object(cli, "get_tls_rpt_records", return_value=([], None)))
            stack.enter_context(patch.object(
                cli, "perform_spoof_test", return_value={"assessment": "LOCAL SMTP RELAY NOT AVAILABLE"}
            ))
            findings = stack.enter_context(patch.object(cli, "build_findings", return_value=[]))
            commentary = stack.enter_context(patch.object(cli, "build_commentary"))
            prompt = stack.enter_context(patch("builtins.input"))
            cli.main()
        prompt.assert_not_called()
        self.assertIsNone(findings.call_args.args[3])
        self.assertIsNone(commentary.call_args.args[3])

    def test_spoof_details_are_displayed_in_a_table(self):
        output = io.StringIO()
        result = {
            "sender": "ceo@example.test", "recipient": "recipient@example.test",
            "subject": "Controlled Spoofing Assessment", "assessment": "UNKNOWN",
            "impact": "Test outcome unavailable.",
        }
        with patch.object(spoof, "console", Console(file=output, width=100)):
            spoof.report_spoof(result)
        text = output.getvalue()
        for value in ("Sender", "ceo@example.test", "Recipient", "recipient@example.test",
                      "Subject", "Controlled Spoofing Assessment"):
            self.assertIn(value, text)

    def test_delivery_prompt_only_follows_accepted_submission(self):
        for assessment in ("MESSAGE SUBMITTED", "REJECTED BY SMTP RELAY"):
            with self.subTest(assessment=assessment), contextlib.ExitStack() as stack:
                stack.enter_context(patch("sys.argv", [
                    "email-audit", "-D", "example.test", "--spoof", "recipient@example.test"
                ]))
                stack.enter_context(patch.object(cli.Path, "mkdir"))
                for name in (
                    "get_spf_record", "get_dmarc_record", "check_mta_sts",
                    "get_mta_sts_policy", "parse_mta_sts_policy", "assess_spf",
                    "assess_dkim_records", "assess_dmarc", "assess_mta_sts",
                    "print_info", "print_assessment", "build_recommendations",
                    "export_json", "export_html", "print_completion_summary", "report_spoof",
                ):
                    stack.enter_context(patch.object(cli, name))
                stack.enter_context(patch.object(cli, "check_dkim_selectors", return_value=[]))
                stack.enter_context(patch.object(cli, "get_tls_rpt_records", return_value=([], None)))
                stack.enter_context(patch.object(
                    cli, "perform_spoof_test", return_value={"assessment": assessment}
                ))
                findings = stack.enter_context(patch.object(cli, "build_findings", return_value=[]))
                stack.enter_context(patch.object(cli, "build_commentary"))
                prompt = stack.enter_context(patch("builtins.input", return_value="yes"))
                cli.main()
                self.assertEqual(prompt.call_count, int(assessment == "MESSAGE SUBMITTED"))
                self.assertEqual(
                    findings.call_args.args[3]["successful"], assessment == "MESSAGE SUBMITTED"
                )

    def test_tool_started_relay_is_cleaned_up_after_delivery_and_on_report_failure(self):
        for fails in (False, True):
            with self.subTest(report_fails=fails), contextlib.ExitStack() as stack:
                events = []
                stack.enter_context(patch("sys.argv", [
                    "email-audit", "-D", "example.test", "--spoof", "recipient@example.test"
                ]))
                stack.enter_context(patch.object(cli.Path, "mkdir"))
                for name in (
                    "get_spf_record", "get_dmarc_record", "check_mta_sts",
                    "get_mta_sts_policy", "parse_mta_sts_policy", "assess_spf",
                    "assess_dkim_records", "assess_dmarc", "assess_mta_sts",
                    "print_info", "print_assessment", "build_recommendations",
                    "export_json", "report_spoof",
                ):
                    stack.enter_context(patch.object(cli, name))
                stack.enter_context(patch.object(cli, "check_dkim_selectors", return_value=[]))
                stack.enter_context(patch.object(cli, "get_tls_rpt_records", return_value=([], None)))
                stack.enter_context(patch.object(cli, "build_findings", return_value=[]))
                stack.enter_context(patch.object(cli, "build_commentary"))

                def perform(domain, recipient, cleanup):
                    cleanup.callback(events.append, "stop")
                    events.append("start")
                    return {"assessment": "MESSAGE SUBMITTED"}

                def report(*args, **kwargs):
                    events.append("report")
                    if fails:
                        raise RuntimeError("report failed")
                    return "report.html"

                stack.enter_context(patch.object(cli, "perform_spoof_test", side_effect=perform))
                stack.enter_context(patch.object(cli, "export_html", side_effect=report))
                stack.enter_context(patch.object(
                    cli, "print_completion_summary", side_effect=lambda *a, **k: events.append("complete")
                ))
                stack.enter_context(patch(
                    "builtins.input", side_effect=lambda *args: events.append("delivery") or "yes"
                ))
                if fails:
                    with self.assertRaisesRegex(RuntimeError, "report failed"):
                        cli.main()
                else:
                    cli.main()
                expected = ["start", "delivery", "report", "stop"]
                if not fails:
                    expected.append("complete")
                self.assertEqual(events, expected)

    def test_existing_relay_stop_prompt_follows_delivery_confirmation(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("sys.argv", [
                "email-audit", "-D", "example.test", "--spoof", "recipient@example.test"
            ]))
            stack.enter_context(patch.object(cli.Path, "mkdir"))
            for name in (
                "get_spf_record", "get_dmarc_record", "check_mta_sts",
                "get_mta_sts_policy", "parse_mta_sts_policy", "assess_spf",
                "assess_dkim_records", "assess_dmarc", "assess_mta_sts",
                "print_info", "print_assessment", "build_recommendations",
                "export_json", "export_html", "print_completion_summary", "report_spoof",
            ):
                stack.enter_context(patch.object(cli, name))
            stack.enter_context(patch.object(cli, "check_dkim_selectors", return_value=[]))
            stack.enter_context(patch.object(cli, "get_tls_rpt_records", return_value=([], None)))
            stack.enter_context(patch.object(cli, "build_findings", return_value=[]))
            stack.enter_context(patch.object(cli, "build_commentary"))
            stack.enter_context(patch.object(spoof, "smtp_server_running", return_value=True))
            stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
            stack.enter_context(patch.object(spoof.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(spoof, "which", return_value="/usr/bin/service"))
            stack.enter_context(patch.object(spoof, "run_command", return_value="queued as 1"))
            service = stack.enter_context(patch.object(spoof.subprocess, "run", side_effect=[
                SimpleNamespace(returncode=0, stdout="", stderr=""),
                SimpleNamespace(returncode=0),
                SimpleNamespace(returncode=3, stdout="", stderr=""),
            ]))
            prompt = stack.enter_context(patch("builtins.input", side_effect=["yes", "yes"]))
            cli.main()
            self.assertIn("successfully delivered", prompt.call_args_list[0].args[0])
            self.assertIn("Stop the existing local Postfix", prompt.call_args_list[1].args[0])
            self.assertEqual(
                [call.args[0][-1] for call in service.call_args_list],
                ["status", "stop", "status"],
            )


class SpoofRelayTests(unittest.TestCase):
    def test_relay_check_requires_an_smtp_greeting(self):
        with patch.object(spoof.smtplib, "SMTP", side_effect=smtplib.SMTPServerDisconnected):
            self.assertFalse(spoof.smtp_server_running())
        with patch.object(spoof.smtplib, "SMTP") as smtp:
            self.assertTrue(spoof.smtp_server_running())
            smtp.assert_called_once_with("localhost", 25, timeout=3)

    def test_available_relay_needs_no_start_prompt(self):
        with patch.object(spoof, "smtp_server_running", return_value=True), \
                patch("builtins.input") as prompt, \
                patch.object(spoof.subprocess, "run") as service, \
                patch.object(spoof.sys.stdin, "isatty", return_value=False), \
                contextlib.ExitStack() as cleanup:
            self.assertIsNone(spoof.ensure_local_smtp(cleanup))
        prompt.assert_not_called()
        service.assert_not_called()

    def test_existing_relay_stop_requires_confirmation(self):
        for answer in ("n", "yes"):
            with self.subTest(answer=answer), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(spoof, "smtp_server_running", return_value=True))
                stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
                stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
                stack.enter_context(patch.object(spoof.os, "geteuid", return_value=0, create=True))
                stack.enter_context(patch.object(spoof, "which", return_value="/usr/bin/service"))
                prompt = stack.enter_context(patch("builtins.input", return_value=answer))
                service = stack.enter_context(patch.object(spoof.subprocess, "run", side_effect=[
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=0),
                    SimpleNamespace(returncode=3, stdout="", stderr=""),
                ]))
                with contextlib.ExitStack() as cleanup:
                    self.assertIsNone(spoof.ensure_local_smtp(cleanup))
                    prompt.assert_not_called()
                    service.assert_not_called()
                prompt.assert_called_once()
                if answer == "yes":
                    self.assertEqual(
                        [call.args[0][-1] for call in service.call_args_list],
                        ["status", "stop", "status"],
                    )
                else:
                    service.assert_not_called()

    def test_existing_relay_stop_does_not_target_inactive_postfix(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(spoof, "smtp_server_running", return_value=True))
            stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
            stack.enter_context(patch.object(spoof.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(spoof, "which", return_value="/usr/bin/service"))
            stack.enter_context(patch("builtins.input", return_value="yes"))
            service = stack.enter_context(patch.object(
                spoof.subprocess, "run", return_value=SimpleNamespace(returncode=3, stdout="", stderr="")
            ))
            with contextlib.ExitStack() as cleanup:
                self.assertIsNone(spoof.ensure_local_smtp(cleanup))
            self.assertEqual([call.args[0][-1] for call in service.call_args_list], ["status"])

    def test_declined_start_skips_sending(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(spoof, "smtp_server_running", return_value=False))
            stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
            stack.enter_context(patch.object(spoof.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(spoof, "which", side_effect=lambda name: f"/usr/bin/{name}"))
            stack.enter_context(patch("builtins.input", return_value="n"))
            start = stack.enter_context(patch.object(spoof.subprocess, "run"))
            send = stack.enter_context(patch.object(spoof, "run_command"))
            result = spoof.perform_spoof_test("example.test", "recipient@example.test", stack)
        self.assertEqual(result["assessment"], "LOCAL SMTP RELAY NOT AVAILABLE")
        self.assertIn("skipped", result["impact"])
        start.assert_not_called()
        send.assert_not_called()

    def test_start_rechecks_relay_before_sending(self):
        for responds in (True, False):
            with self.subTest(responds=responds), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(
                    spoof, "smtp_server_running", side_effect=[False, responds]
                ))
                stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
                stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
                stack.enter_context(patch.object(spoof.os, "geteuid", return_value=1000, create=True))
                stack.enter_context(patch.object(
                    spoof, "which", side_effect=lambda name: f"/usr/bin/{name}"
                ))
                stack.enter_context(patch("builtins.input", return_value="yes"))
                service = stack.enter_context(patch.object(
                    spoof.subprocess, "run", side_effect=[
                        SimpleNamespace(returncode=3, stdout="", stderr=""),
                        SimpleNamespace(returncode=0),
                        SimpleNamespace(returncode=0),
                        SimpleNamespace(returncode=3, stdout="", stderr=""),
                    ]
                ))
                send = stack.enter_context(patch.object(spoof, "run_command", return_value="queued as 1"))
                with contextlib.ExitStack() as cleanup:
                    result = spoof.perform_spoof_test("example.test", "recipient@example.test", cleanup)
                    self.assertEqual(service.call_count, 2)
                if responds:
                    self.assertEqual(result["assessment"], "MESSAGE SUBMITTED")
                    self.assertIn("Subject: Controlled Spoofing Assessment", send.call_args.args[0])
                else:
                    self.assertIn("no SMTP service responded", result["impact"])
                    send.assert_not_called()
                self.assertEqual(
                    [call.args[0][-1] for call in service.call_args_list],
                    ["status", "start", "stop", "status"],
                )
                self.assertEqual(
                    service.call_args_list[1].args[0],
                    ["/usr/bin/sudo", "/usr/bin/service", "postfix", "start"],
                )

    def test_noninteractive_missing_relay_does_not_prompt(self):
        with patch.object(spoof, "smtp_server_running", return_value=False), \
                patch.object(spoof.sys.stdin, "isatty", return_value=False), \
                patch("builtins.input") as prompt, contextlib.ExitStack() as cleanup:
            self.assertIn("Start a local SMTP relay", spoof.ensure_local_smtp(cleanup))
        prompt.assert_not_called()

    def test_failed_service_start_is_reported(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(spoof, "smtp_server_running", return_value=False))
            stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
            stack.enter_context(patch.object(spoof.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(spoof, "which", return_value="/usr/bin/service"))
            stack.enter_context(patch("builtins.input", return_value="y"))
            service = stack.enter_context(patch.object(
                spoof.subprocess, "run", side_effect=[
                    SimpleNamespace(returncode=3, stdout="", stderr=""),
                    SimpleNamespace(returncode=1),
                    SimpleNamespace(returncode=0),
                    SimpleNamespace(returncode=3, stdout="", stderr=""),
                ]
            ))
            with contextlib.ExitStack() as cleanup:
                self.assertIn("startup failed (exit code 1)", spoof.ensure_local_smtp(cleanup))
            self.assertEqual(
                [call.args[0][-1] for call in service.call_args_list],
                ["status", "start", "stop", "status"],
            )

    def test_running_postfix_without_local_listener_is_not_stopped(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(spoof, "smtp_server_running", return_value=False))
            stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
            stack.enter_context(patch.object(spoof.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(spoof, "which", return_value="/usr/bin/service"))
            stack.enter_context(patch("builtins.input", return_value="y"))
            service = stack.enter_context(patch.object(
                spoof.subprocess, "run", return_value=SimpleNamespace(returncode=0)
            ))
            with contextlib.ExitStack() as cleanup:
                self.assertIn("already running", spoof.ensure_local_smtp(cleanup))
            self.assertEqual([call.args[0][-1] for call in service.call_args_list], ["status"])

    def test_cleanup_runs_if_sending_raises(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(
                spoof, "smtp_server_running", side_effect=[False, True]
            ))
            stack.enter_context(patch.object(spoof.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(spoof.sys, "platform", "linux"))
            stack.enter_context(patch.object(spoof.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(spoof, "which", return_value="/usr/bin/service"))
            stack.enter_context(patch("builtins.input", return_value="y"))
            service = stack.enter_context(patch.object(
                spoof.subprocess, "run", side_effect=[
                    SimpleNamespace(returncode=3, stdout="", stderr=""),
                    SimpleNamespace(returncode=0),
                    SimpleNamespace(returncode=0),
                    SimpleNamespace(returncode=3, stdout="", stderr=""),
                ]
            ))
            stack.enter_context(patch.object(spoof, "run_command", side_effect=RuntimeError("send failed")))
            with self.assertRaisesRegex(RuntimeError, "send failed"):
                with contextlib.ExitStack() as cleanup:
                    spoof.perform_spoof_test("example.test", "recipient@example.test", cleanup)
            self.assertEqual(
                [call.args[0][-1] for call in service.call_args_list],
                ["status", "start", "stop", "status"],
            )

    def test_cleanup_failure_is_reported(self):
        with patch.object(spoof.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, "Postfix stop failed"):
                spoof._stop_postfix(["service", "postfix"])

    def test_cleanup_reports_when_postfix_is_still_running(self):
        with patch.object(spoof.subprocess, "run", side_effect=[
            SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=0, stdout="still running", stderr=""),
        ]):
            with self.assertRaisesRegex(RuntimeError, "Could not confirm Postfix stopped.*still running"):
                spoof._stop_postfix(["service", "postfix"])


if __name__ == "__main__":
    unittest.main()
