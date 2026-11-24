import base64
import contextlib
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from email_audit.dns.dkim import assess_dkim, assess_dkim_key, assess_dkim_records, check_dkim_selectors
from email_audit.dns.dmarc import assess_dmarc
from email_audit.dns.mta_sts import assess_mta_sts, parse_mta_sts_policy
from email_audit.dns.spf import assess_spf
from email_audit.dns.tls_rpt import assess_tls_rpt, get_tls_rpt_records
from email_audit.reporting.commentary import build_commentary
from email_audit.reporting.findings import build_findings
from email_audit.reporting.remediation import build_recommendations
from email_audit.reporting.sureformat import export_sureformat


@contextlib.contextmanager
def temporary_working_directory():
    with tempfile.TemporaryDirectory() as directory:
        old = os.getcwd()
        try:
            os.chdir(directory)
            yield
        finally:
            os.chdir(old)


def dkim_record(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    encoded = base64.b64encode(der).decode("ascii")
    return f'"v=DKIM1; k=rsa; p={encoded[:100]}" "{encoded[100:]}"'


class DkimKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.weak = dkim_record(2047)
        cls.strong = dkim_record(2048)

    def test_exact_rsa_threshold_and_split_txt(self):
        self.assertEqual(assess_dkim_key(self.weak)[:2], ("WEAK", 2047))
        self.assertEqual(assess_dkim_key(self.strong)[:2], ("ADEQUATE", 2048))

    def test_malformed_revoked_and_non_rsa_are_not_weak(self):
        for record in ('"v=DKIM1; p=;"', '"v=DKIM1; p=not-base64;"',
                       '"v=DKIM1; p=abc; p=abc"'):
            with self.subTest(record=record):
                self.assertEqual(assess_dkim_key(record)[0], "UNKNOWN")
        self.assertEqual(assess_dkim_key('"v=DKIM1; k=ed25519; p=abc"')[0], "NOT APPLICABLE")

    def test_all_common_selectors_and_sample_key_remain_in_findings(self):
        records = [("default", self.weak, True), ("selector1", self.strong, True)]
        with patch("email_audit.dns.dkim.check_dkim_dns") as query:
            query.side_effect = lambda domain, selector: next(
                (record for record in records if record[0] == selector), ("", "", False)
            )
            discovered = check_dkim_selectors("example.test")
            self.assertEqual(query.call_count, 4)
        dkim = assess_dkim_records(discovered, selected=("sample", self.strong, True))
        results = [
            assess_spf("v=spf1 -all"), dkim, assess_dmarc("v=DMARC1; p=reject"),
            assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy("mode: enforce")),
        ]
        weak = [item for item in build_findings("example.test", results)
                if item["id"] == "weak-dkim-rsa-key"]
        self.assertEqual(len(weak), 1)
        self.assertIn("default", weak[0]["description"])
        self.assertIn("default", build_commentary("example.test", results))
        self.assertIn("default", build_recommendations(results))
        after_error = assess_dkim_records(discovered, selected=("default", "unverified", False))
        self.assertEqual(after_error["key_observations"][0]["key_assessment"], "WEAK")

    def test_weak_key_is_reported_with_selector_and_sureformat_id(self):
        results = [
            assess_spf("v=spf1 -all"), assess_dkim("selector1", self.weak, True),
            assess_dmarc("v=DMARC1; p=reject"),
            assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy("mode: enforce")),
            assess_tls_rpt(["v=TLSRPTv1; rua=mailto:reports@example.test"]),
        ]
        findings = build_findings("example.test", results)
        weak = next(item for item in findings if item["id"] == "weak-dkim-rsa-key")
        self.assertIn("selector1", weak["description"])
        self.assertIn("2047", weak["description"])
        self.assertIn("2047-bit", build_commentary("example.test", results))
        self.assertIn("2048 bits", build_recommendations(results))
        with temporary_working_directory():
            filename, _ = export_sureformat("example.test", findings)
            root = ET.parse(filename).getroot()
            self.assertIn("SC-2187", [node.get("id") for node in root.findall(".//vulnerability")])


class TlsRptTests(unittest.TestCase):
    def test_valid_records_and_unrelated_txt(self):
        for record in (
            "v=TLSRPTv1; rua=mailto:reports@example.test",
            "v=TLSRPTv1 ; rua=https://reports.example.test/path; custom=value;",
            "v=TLSRPTv1; rua=mailto:a@example.test, https://reports.example.test/",
        ):
            with self.subTest(record=record):
                self.assertEqual(assess_tls_rpt(["unrelated", record])["assessment"], "PRESENT")
        self.assertEqual(assess_tls_rpt(["unrelated"])["assessment"], "MISSING")

    def test_invalid_records(self):
        for records in (
            ["v=TLSRPTv1"],
            ["v=TLSRPTv1; rua="],
            ["v=TLSRPTv1; rua=http://example.test/"],
            ["v=TLSRPTv1; rua=mailto:not-an-address"],
            ["v=TLSRPTv1; rua=mailto:a@example.test; rua=mailto:b@example.test"],
            ["v=TLSRPTv1; rua=mailto:a@example.test", "v=TLSRPTv1; rua=mailto:b@example.test"],
            ["v=TLSRPTv1; rua=mailto:a@example.test;;"],
        ):
            with self.subTest(records=records):
                self.assertEqual(assess_tls_rpt(records)["assessment"], "INVALID")

    def test_dns_failure_is_inconclusive_and_chunks_are_joined(self):
        with patch("email_audit.dns.tls_rpt.dns.resolver.resolve") as resolve:
            resolve.return_value = [Mock(strings=(b"v=TLSRPTv1;", b"rua=mailto:a@example.test"))]
            records, error = get_tls_rpt_records("example.test")
            self.assertIsNone(error)
            self.assertEqual(assess_tls_rpt(records)["assessment"], "PRESENT")
            resolve.side_effect = dns.exception.Timeout("DNS timed out")
            records, error = get_tls_rpt_records("example.test")
            self.assertEqual(assess_tls_rpt(records, error)["assessment"], "UNKNOWN")
            resolve.side_effect = dns.resolver.NXDOMAIN()
            records, error = get_tls_rpt_records("example.test")
            self.assertEqual(assess_tls_rpt(records, error)["assessment"], "MISSING")

    def test_tls_findings_and_sureformat(self):
        base = [
            assess_spf("v=spf1 -all"), assess_dkim("", "", False),
            assess_dmarc("v=DMARC1; p=reject"),
            assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy("mode: enforce")),
        ]
        for records, finding_id, xml_id in (
            ([], "missing-tls-rpt", "SC-6840"),
            (["v=TLSRPTv1; rua=oops"], "invalid-tls-rpt", "SC-6841"),
        ):
            with self.subTest(finding=finding_id), temporary_working_directory():
                results = base + [assess_tls_rpt(records)]
                findings = build_findings("example.test", results)
                self.assertIn(finding_id, [item["id"] for item in findings])
                self.assertIn("TLS-RPT", build_commentary("example.test", results))
                self.assertIn("TLS-RPT", build_recommendations(results))
                filename, _ = export_sureformat("example.test", findings)
                root = ET.parse(filename).getroot()
                self.assertIn(xml_id, [node.get("id") for node in root.findall(".//vulnerability")])
        unknown = base + [assess_tls_rpt([], "DNS timeout")]
        self.assertFalse(any("tls-rpt" in item["id"] for item in build_findings("example.test", unknown)))


if __name__ == "__main__":
    unittest.main()
