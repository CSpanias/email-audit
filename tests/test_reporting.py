import json
import re
import unittest
from unittest.mock import Mock, patch

from email_audit.dns.dkim import assess_dkim
from email_audit.dns.dmarc import assess_dmarc
from email_audit.dns.mta_sts import assess_mta_sts, parse_mta_sts_policy
from email_audit.dns.spf import assess_spf
from email_audit.dns.tls_rpt import assess_tls_rpt
from email_audit.reporting.definitions import load_definitions
from email_audit.reporting.executive_summary import build_executive_summary
from email_audit.reporting.findings import build_findings
from email_audit.reporting.html import render_html


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.results = [
            assess_spf("v=spf1 -all"),
            assess_dkim("selector1", "v=DKIM1; p=key", True),
            assess_dmarc("v=DMARC1; p=reject"),
            assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy("mode: enforce")),
        ]

    def test_findings_use_yaml_description(self):
        definitions = {"email-audit": {"description": "Review for {domain}"}}
        with patch("email_audit.reporting.findings.load_definitions", return_value=definitions):
            findings = build_findings("example.test", self.results)
        self.assertEqual(findings, [{"id": "email-audit", "description": "Review for example.test"}])

    def test_invalid_yaml_is_reported(self):
        load_definitions.cache_clear()
        resource = Mock()
        resource.joinpath.return_value.joinpath.return_value.read_text.return_value = "[invalid"
        with patch("email_audit.reporting.definitions.files", return_value=resource):
            with self.assertRaisesRegex(RuntimeError, "Unable to load reporting definitions"):
                load_definitions("broken")
        load_definitions.cache_clear()

    def test_html_escapes_external_content_and_blocks_active_markup(self):
        report = render_html(
            "<example>",
            "## Section\n\n<script>alert(1)</script>\n\n"
            "[unsafe](javascript:alert(1)) ![image](https://example.test/x)\n\n"
            "[reference](https://example.test/)",
            "Recommendation",
            self.results,
            [{"id": "<id>", "description": "<img src=x onerror=alert(1)>"}],
        )
        self.assertIn("&lt;example&gt;", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertIn('href="https://example.test/"', report)
        self.assertNotIn("&lt;img src=x onerror=alert(1)&gt;", report)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertNotIn("<img", report)
        self.assertNotIn('href="javascript:', report)

    def test_copy_controls_preserve_markdown_and_escape_script_data(self):
        commentary = "### Control\n\n- Item </script><script>alert(1)</script>"
        recommendations = "Recommendation\n\n### References\n\n- [ref](https://example.test)"
        report = render_html("example.test", commentary, recommendations, self.results, [])
        match = re.search(
            r'<script id="markdown-data" type="application/json">(.*?)</script>',
            report,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        data = json.loads(match.group(1))
        self.assertEqual(data["technical"], commentary)
        self.assertEqual(data["recommendations"], recommendations)
        self.assertIn(f"## Technical Commentary\n\n{commentary}", data["all"])
        self.assertIn(f"## Recommendations\n\n{recommendations}", data["all"])
        self.assertNotIn("</script><script>alert(1)</script>", report)
        for key in ("all", "executive", "technical", "recommendations"):
            self.assertIn(f'data-copy="{key}"', report)

    def test_spoof_result_is_reflected_in_html_summary(self):
        report = render_html(
            "example.test", "", "", self.results, [],
            spoof_result={"successful": True},
        )
        self.assertIn("a message pretending to come from example.test was delivered", report)

    def test_summary_separates_sample_results_from_impersonation_and_combines_issues(self):
        self.results[1].update(key_assessment="WEAK", key_bits=1024, selector="selector1")
        self.results[3] = assess_mta_sts("", parse_mta_sts_policy(""))
        self.results.append(assess_tls_rpt([]))
        summary = build_executive_summary(
            "example.test", self.results,
            {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            {"successful": True},
        )
        paragraphs = summary.split("\n\n")
        self.assertIn("supplied email passed", paragraphs[1])
        self.assertIn("does not demonstrate", paragraphs[1])
        self.assertIn("pretending to come from example.test was delivered", paragraphs[2])
        self.assertIn("intercepted or altered", paragraphs[3])
        self.assertIn("weak safeguard", paragraphs[3])
        self.assertIn("may go unreported", paragraphs[3])
        self.assertIn("successful impersonation test", paragraphs[4])
        for technical_term in ("SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT", "1024", "selector1"):
            self.assertNotIn(technical_term, summary)

    def test_summary_does_not_treat_inconclusive_results_as_missing_or_passed(self):
        self.results[3] = assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy(""))
        self.results.append(assess_tls_rpt([], error="timeout"))
        summary = build_executive_summary(
            "example.test", self.results, {"spf": "pass", "dkim": "temperror"}
        )
        self.assertIn("did not contain enough information", summary)
        self.assertIn("protection for email in transit could not be confirmed", summary)
        self.assertIn("Reporting of problems protecting email in transit could not be confirmed", summary)
        self.assertNotIn("supplied email passed", summary)

    def test_summary_reports_failed_sample_without_claiming_controls_malfunctioned(self):
        summary = build_executive_summary(
            "example.test", self.results, {"spf": "fail", "dkim": "pass", "dmarc": "pass"}
        )
        self.assertIn("checks recorded for the supplied email failed", summary)
        self.assertNotIn("functioning as intended", summary)

    def test_summary_handles_no_sample_and_non_enforcing_transport(self):
        self.results[3] = assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy("mode: testing"))
        self.results.append(assess_tls_rpt(["v=TLSRPTv1; rua=invalid"]))
        summary = build_executive_summary("example.test", self.results)
        self.assertIn("No email sample was supplied", summary)
        self.assertIn("not fully enforced", summary)
        self.assertIn("may go unreported", summary)

    def test_summary_highlights_weak_sender_protections_without_spoof_test(self):
        self.results[2] = assess_dmarc("v=DMARC1; p=none")
        summary = build_executive_summary(
            "example.test", self.results, {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        )
        self.assertIn("not sufficiently restrictive", summary)
        self.assertIn("further action is needed", summary)


if __name__ == "__main__":
    unittest.main()
