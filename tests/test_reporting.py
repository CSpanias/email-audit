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
from email_audit.reporting.commentary import build_commentary
from email_audit.reporting.executive_summary import build_executive_summary
from email_audit.reporting.findings import build_findings
from email_audit.reporting.html import render_html
from email_audit.reporting.remediation import build_recommendations


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
        self.assertIn("successfully delivered a message impersonating example.test", report)

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
        self.assertIn("supplied email passed the checks recorded by the receiving system", paragraphs[1])
        self.assertIn("successfully delivered a message impersonating example.test", paragraphs[2])
        self.assertIn("interception or alteration", paragraphs[3])
        self.assertIn("weak verification safeguard was identified", paragraphs[3])
        self.assertIn("Reporting of email delivery security issues was not identified", paragraphs[3])
        self.assertIn("reduce exposure to impersonation", paragraphs[4])
        for technical_term in ("SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT", "1024", "selector1"):
            self.assertNotIn(technical_term, summary)

    def test_summary_does_not_treat_inconclusive_results_as_missing_or_passed(self):
        self.results[3] = assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy(""))
        self.results.append(assess_tls_rpt([], error="timeout"))
        summary = build_executive_summary(
            "example.test", self.results, {"spf": "pass", "dkim": "temperror"}
        )
        self.assertIn("did not contain enough information", summary)
        self.assertIn("protection for messages in transit could not be confirmed", summary)
        self.assertIn("Reporting of delivery security issues could not be confirmed", summary)
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
        self.assertIn("Reporting of email delivery security issues was not configured correctly", summary)

    def test_summary_highlights_weak_sender_protections_without_spoof_test(self):
        self.results[2] = assess_dmarc("v=DMARC1; p=none")
        summary = build_executive_summary(
            "example.test", self.results, {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        )
        self.assertIn("policy did not request that recipients block messages that failed verification", summary)
        self.assertIn("areas requiring further review", summary)

    def test_weak_dkim_selector_is_formatted_and_its_risk_explained(self):
        self.results[1].update(key_assessment="WEAK", key_bits=1024, selector="selector1")
        commentary = build_commentary("example.test", self.results)
        recommendations = build_recommendations(self.results)
        self.assertIn("DKIM selector `selector1` uses a 1024-bit RSA public key", commentary)
        self.assertIn("forge signatures and impersonate the domain", commentary)
        self.assertIn("DKIM selector `selector1`", recommendations)
        report = render_html("example.test", commentary, recommendations, self.results, [])
        self.assertIn("<code>selector1</code>", report)

    def test_spf_policies_are_formatted_as_inline_code(self):
        for policy in ("-all", "~all", "+all"):
            with self.subTest(policy=policy):
                self.results[0] = assess_spf(f"v=spf1 {policy}")
                commentary = build_commentary("example.test", self.results)
                self.assertEqual(commentary.count(f"`{policy}`"), 2)
                report = render_html("example.test", commentary, "", self.results, [])
                self.assertEqual(report.count(f"<code>{policy}</code>"), 2)
                if policy == "+all":
                    self.assertIn("`+all`", build_recommendations(self.results))

    def test_dmarc_monitoring_explanation_follows_the_list_as_a_paragraph(self):
        for record in ("v=DMARC1; p=none", "v=DMARC1; p=none; rua=mailto:a@example.test"):
            with self.subTest(record=record):
                self.results[2] = assess_dmarc(record)
                commentary = build_commentary("example.test", self.results)
                self.assertIn("\n\nAlthough this configuration provides visibility", commentary)
                report = render_html("example.test", commentary, "", self.results, [])
                self.assertIn("</ul>\n<p>Although this configuration", report)

    def test_spoofing_explanation_uses_observed_dmarc_policy_without_assuming_cause(self):
        for policy, expected in (
            ("none", "The DMARC policy is `p=none`"),
            ("reject", "requests rejection of messages that fail DMARC (`p=reject`)"),
            ("quarantine", "requests quarantine rather than rejection"),
        ):
            with self.subTest(policy=policy):
                self.results[2] = assess_dmarc(f"v=DMARC1; p={policy}")
                commentary = build_commentary(
                    "example.test", self.results, spoof_result={"successful": True}
                )
                spoof_section = commentary.split("### Controlled Spoofing Assessment", 1)[1]
                self.assertIn("SPF, DKIM and DMARC records were identified", spoof_section)
                self.assertIn(expected, spoof_section)
                self.assertIn("authentication results were not analysed", spoof_section)
                self.assertIn("determine why it was delivered", spoof_section)

    def test_spoofing_explanation_does_not_claim_missing_controls_are_present(self):
        self.results[0] = assess_spf("")
        self.results[2] = assess_dmarc("")
        commentary = build_commentary("example.test", self.results, spoof_result={"successful": True})
        spoof_section = commentary.split("### Controlled Spoofing Assessment", 1)[1]
        self.assertIn("Not all SPF, DKIM and DMARC controls could be confirmed", spoof_section)
        self.assertIn("No DMARC policy was identified", spoof_section)
        self.assertNotIn("records were identified", spoof_section)

    def test_unconfirmed_spoof_delivery_does_not_claim_a_policy_explanation(self):
        self.results[2] = assess_dmarc("v=DMARC1; p=none")
        commentary = build_commentary("example.test", self.results, spoof_result={"successful": False})
        spoof_section = commentary.split("### Controlled Spoofing Assessment", 1)[1]
        self.assertIn("did not result in confirmed delivery", spoof_section)
        self.assertNotIn("The DMARC policy is", spoof_section)


if __name__ == "__main__":
    unittest.main()
