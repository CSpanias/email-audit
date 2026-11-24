import unittest
from unittest.mock import Mock, patch

from email_audit.dns.dkim import assess_dkim
from email_audit.dns.dmarc import assess_dmarc
from email_audit.dns.mta_sts import assess_mta_sts, parse_mta_sts_policy
from email_audit.dns.spf import assess_spf
from email_audit.reporting.definitions import load_definitions
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
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", report)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<img", report)
        self.assertNotIn('href="javascript:', report)

    def test_spoof_result_is_reflected_in_html_summary(self):
        report = render_html(
            "example.test", "", "", self.results, [],
            spoof_result={"successful": True},
        )
        self.assertIn("could be successfully spoofed", report)


if __name__ == "__main__":
    unittest.main()
