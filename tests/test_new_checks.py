import base64
import contextlib
import io
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from email_audit.cli import _lookup_record, process_email_sample
from email_audit.dns.dkim import assess_dkim, assess_dkim_key, assess_dkim_records, check_dkim_selectors
from email_audit.dns.dmarc import assess_dmarc, get_dmarc_record
from email_audit.dns.lookup import DNSLookupError
from email_audit.dns.mta_sts import (
    MtaStsPolicyError, assess_mta_sts, check_mta_sts, get_mta_sts_policy,
    parse_mta_sts_policy,
)
from email_audit.dns.spf import assess_spf, get_spf_record
from email_audit.dns.tls_rpt import assess_tls_rpt, get_tls_rpt_records
from email_audit.email.eml import parse_eml_file
from email_audit.reporting.commentary import build_commentary
from email_audit.reporting.findings import build_findings
from email_audit.reporting.executive_summary import build_executive_summary
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


class DnsAndSpfTests(unittest.TestCase):
    def test_multiple_records_and_broad_or_invalid_address_mechanisms(self):
        with patch("email_audit.dns.spf.get_txt_records", return_value=[
            "v=spf1 -all", "v=spf1 +all",
        ]):
            multiple = assess_spf(get_spf_record("example.test"))
        self.assertEqual(multiple["assessment"], "UNKNOWN")
        self.assertIn("multiple SPF records", multiple["record_error"])
        for mechanism in ("ip4:0.0.0.0/0", "+ip6:::/0"):
            with self.subTest(mechanism=mechanism):
                result = assess_spf(f"v=spf1 {mechanism} -all")
                self.assertEqual(result["assessment"], "INSECURE")
                self.assertEqual(result["broad_mechanism"], mechanism)
        self.assertEqual(assess_spf("v=spf1 -ip4:0.0.0.0/0 -all")["assessment"], "SECURE")
        self.assertEqual(assess_spf("v=spf1 -ip4:0.0.0.0/0 ip4:0.0.0.0/0 -all")["assessment"], "SECURE")
        self.assertEqual(assess_spf("v=spf1 -all ip4:0.0.0.0/0")["assessment"], "SECURE")
        self.assertEqual(assess_spf("v=spf1 ip4:bad -all")["assessment"], "UNKNOWN")
        self.assertEqual(assess_spf("v=spf1 ip4:192.0.2.0/255.255.255.0 -all")["assessment"], "UNKNOWN")

    def test_first_all_mechanism_controls_assessment_and_reporting(self):
        cases = (
            ("+all -all", "INSECURE", "+all", "Permissive (`+all`)"),
            ("all -all", "INSECURE", "all", "Permissive (`all`)"),
            ("~all -all", "ACCEPTABLE", "~all", "Soft Fail (`~all`)"),
            ("-all +all", "SECURE", "-all", "Hard Fail (`-all`)"),
            ("?all -all", "UNKNOWN", "?all", "Unknown"),
            ("-ALL +all", "SECURE", "-all", "Hard Fail (`-all`)"),
        )
        for mechanisms, status, policy, config in cases:
            with self.subTest(mechanisms=mechanisms):
                spf = assess_spf(f"v=spf1 {mechanisms}")
                results = [spf, assess_dkim("", "", False), assess_dmarc(""),
                           assess_mta_sts("", parse_mta_sts_policy(""))]
                self.assertEqual((spf["assessment"], spf["all_policy"]), (status, policy))
                self.assertIn(f"| SPF     | {config}", build_commentary("example.test", results))
                ids = [item["id"] for item in build_findings("example.test", results)]
                self.assertEqual("permissive-spf" in ids, status == "INSECURE")

    def test_absence_and_failed_lookups_are_distinct_for_all_dns_checks(self):
        queries = (get_spf_record, get_dmarc_record, check_mta_sts)
        assessors = (
            lambda record, error: assess_spf(record, error),
            lambda record, error: assess_dmarc(record, error),
            lambda record, error: assess_mta_sts(record, parse_mta_sts_policy(""), error),
        )
        with patch("email_audit.dns.lookup.dns.resolver.resolve") as resolve:
            for failure in (dns.exception.Timeout(), dns.resolver.NoNameservers(),
                            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")):
                for query, assess in zip(queries, assessors):
                    with self.subTest(failure=type(failure).__name__, query=query.__name__):
                        resolve.side_effect = failure
                        record, error = _lookup_record(query, "example.test")
                        self.assertEqual(assess(record, error)["assessment"], "UNKNOWN")
                        self.assertTrue(error)
            for absence in (dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()):
                for query, assess in zip(queries, assessors):
                    with self.subTest(absence=type(absence).__name__, query=query.__name__):
                        resolve.side_effect = absence
                        record, error = _lookup_record(query, "example.test")
                        self.assertIsNone(error)
                        self.assertEqual(assess(record, error)["assessment"], "MISSING")

    def test_dkim_partial_failure_and_dns_failures_do_not_generate_missing_findings(self):
        with patch("email_audit.dns.lookup.dns.resolver.resolve") as resolve:
            resolve.side_effect = [dns.exception.Timeout(), dns.resolver.NoAnswer(),
                                   dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
            errors = []
            records = check_dkim_selectors("example.test", errors)
        dkim = assess_dkim_records(records, dns_errors=errors)
        results = [assess_spf("", "timeout"), dkim, assess_dmarc("", "resolver failure"),
                   assess_mta_sts("", parse_mta_sts_policy(""), "timeout"),
                   assess_tls_rpt([], "timeout")]
        self.assertEqual([item["assessment"] for item in results], ["UNKNOWN"] * 5)
        self.assertIn("incomplete", dkim["breakdown"][0])
        self.assertEqual([item["id"] for item in build_findings("example.test", results)],
                         ["email-audit"])
        commentary = build_commentary("example.test", results, spoof_result={"successful": True})
        self.assertIn("| SPF     | Unknown", commentary)
        self.assertIn("| DMARC   | Unknown", commentary)
        self.assertIn("DNS lookup failed", commentary)
        self.assertNotIn("an MTA-STS DNS record was", commentary)
        self.assertNotIn("SPF, DKIM and DMARC records were identified", commentary)
        self.assertIn("DNS lookup failures", build_recommendations(results))
        self.assertNotIn("identified the absence", build_recommendations(results))
        self.assertNotIn("controls were identified", build_executive_summary("example.test", results))

    def test_discovered_dkim_key_is_retained_when_another_selector_lookup_fails(self):
        answer = Mock(strings=(dkim_record(2048).replace('" "', '').strip('"').encode(),))
        with patch("email_audit.dns.lookup.dns.resolver.resolve") as resolve:
            resolve.side_effect = [[answer], dns.exception.Timeout(),
                                   dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
            errors = []
            records = check_dkim_selectors("example.test", errors)
        dkim = assess_dkim_records(records, dns_errors=errors)
        self.assertEqual(dkim["assessment"], "PRESENT")
        self.assertEqual(len(errors), 1)
        results = [assess_spf("v=spf1 -all"), dkim, assess_dmarc("v=DMARC1; p=reject"),
                   assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy("mode: enforce"))]
        self.assertIn("discovery was incomplete", build_commentary("example.test", results))
        self.assertIn("DNS lookup failures", build_recommendations(results))

    def test_sample_selector_lookup_failure_preserves_discovered_key(self):
        records = [("default", dkim_record(2048), True)]
        results = [assess_spf("v=spf1 -all"), assess_dkim_records(records)]
        errors = []
        auth = {"dkim_selector": "sample", "dkim_domain": "example.test", "dkim": "pass"}
        with patch("email_audit.cli.parse_eml_file", return_value=auth), \
             patch("email_audit.cli.check_dkim_dns", side_effect=DNSLookupError("timeout")):
            self.assertEqual(process_email_sample("example.test", "sample.eml",
                                                  results, records, errors), auth)
        self.assertEqual(results[1]["assessment"], "PRESENT")
        self.assertEqual(results[1]["selector"], "default")
        self.assertEqual(results[1]["dns_errors"], ["timeout"])
        self.assertNotIn("supplied email sample", results[1]["impact"])


class DmarcCoverageTests(unittest.TestCase):
    def test_duplicate_records_and_invalid_policy_tags_are_inconclusive(self):
        with patch("email_audit.dns.dmarc.get_txt_records", return_value=[
            "v=DMARC1; p=reject", "v=DMARC1; p=none",
        ]):
            result = assess_dmarc(get_dmarc_record("example.test"))
        self.assertEqual(result["assessment"], "UNKNOWN")
        for tags in ("p=none; p=reject", "p=reject; adkim=invalid",
                     "p=reject; sp=invalid"):
            with self.subTest(tags=tags):
                result = assess_dmarc(f"v=DMARC1; {tags}")
                self.assertEqual(result["assessment"], "UNKNOWN")
                self.assertTrue(result["record_errors"])

    def test_policy_coverage_changes_assessment(self):
        cases = (
            ("p=reject", "SECURE", False),
            ("p=reject; pct=100", "SECURE", False),
            ("p=reject; pct=0", "ACCEPTABLE", True),
            ("p=reject; pct=99", "ACCEPTABLE", True),
            ("p=quarantine; pct=100", "ACCEPTABLE", False),
            ("p=quarantine; pct=0", "INSECURE", True),
            ("p=quarantine; pct=1", "INSECURE", True),
            ("p=none; pct=0", "INSECURE", False),
            ("p=reject; t=y", "ACCEPTABLE", True),
            ("p=quarantine; t=y", "INSECURE", True),
            ("p=reject; t=n", "SECURE", False),
            ("p=none; t=y", "INSECURE", False),
            ("p=REJECT; PCT = 50", "ACCEPTABLE", True),
        )
        for tags, status, limited in cases:
            with self.subTest(tags=tags):
                result = assess_dmarc(f"v=DMARC1; {tags}")
                self.assertEqual(result["assessment"], status)
                self.assertEqual(result["coverage_limited"], limited)

    def test_malformed_and_duplicate_coverage_tags_are_inconclusive(self):
        for tags in ("pct=-1", "pct=101", "pct=1.5", "pct=", "pct=0000",
                     "pct=0; pct=100", "t=maybe", "t=y; t=n"):
            with self.subTest(tags=tags):
                result = assess_dmarc(f"v=DMARC1; p=reject; {tags}")
                self.assertEqual(result["assessment"], "UNKNOWN")
                self.assertTrue(result["coverage_errors"])
                self.assertFalse(result["coverage_limited"])
                self.assertIn("could not be determined", result["impact"])


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
        self.assertEqual(assess_dkim_key('"v=DKIM1; k=ed25519; p=abc"')[0], "UNKNOWN")
        encoded = base64.b64encode(b"a" * 32).decode()
        self.assertEqual(assess_dkim_key(f"v=DKIM1; k=ed25519; p={encoded}")[0], "NOT APPLICABLE")
        for record in ("v=DKIM1; p=", "v=DKIM1; p=not-base64"):
            result = assess_dkim("sample", record, True)
            self.assertEqual(result["assessment"], "UNKNOWN")
            self.assertTrue(result["key_error"])

    def test_valid_key_is_not_hidden_by_unusable_first_selector(self):
        result = assess_dkim_records([
            ("default", "v=DKIM1; p=", True), ("selector1", self.strong, True),
        ])
        self.assertEqual(result["assessment"], "PRESENT")
        self.assertEqual(result["selector"], "selector1")
        self.assertEqual(result["key_observations"][0]["key_assessment"], "UNKNOWN")

    def test_sample_signing_domain_is_queried_without_replacing_target_assessment(self):
        records = [("default", self.strong, True)]
        results = [assess_spf("v=spf1 -all"), assess_dkim_records(records)]
        auth = {"dkim_selector": "external", "dkim_domain": "signer.example.test", "dkim": "pass"}
        with patch("email_audit.cli.parse_eml_file", return_value=auth), \
             patch("email_audit.cli.check_dkim_dns", return_value=("external", self.strong, True)) as query:
            result = process_email_sample("example.test", "sample.eml", results, records, [])
        query.assert_called_once_with("signer.example.test", "external")
        self.assertEqual(results[1]["selector"], "default")
        self.assertEqual(result["dkim_sample_key"]["assessment"], "PRESENT")

    def test_sample_without_signing_domain_is_not_looked_up_against_target(self):
        results = [assess_spf("v=spf1 -all"), assess_dkim_records([])]
        auth = {"dkim_selector": "external", "dkim_domain": "", "dkim": "pass"}
        with patch("email_audit.cli.parse_eml_file", return_value=auth), \
             patch("email_audit.cli.check_dkim_dns") as query:
            process_email_sample("example.test", "sample.eml", results, [], [])
        query.assert_not_called()


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


class MtaStsValidationTests(unittest.TestCase):
    def test_https_failures_remain_inconclusive_with_their_reason(self):
        with patch("email_audit.dns.mta_sts.urllib.request.urlopen", side_effect=OSError("network unavailable")):
            with self.assertRaisesRegex(MtaStsPolicyError, "network unavailable") as error:
                get_mta_sts_policy("example.test")
        result = assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy(""), policy_error=str(error.exception))
        self.assertEqual(result["assessment"], "UNKNOWN")
        self.assertIn("network unavailable", result["breakdown"][0])

    def test_dns_and_policy_require_valid_fields(self):
        valid = "version: STSv1\nmode: enforce\nmx: *.example.test\nmax_age: 86400"
        with patch("email_audit.dns.mta_sts.get_txt_records", return_value=["unrelated"]):
            self.assertEqual(check_mta_sts("example.test"), "")
        for record, policy in (
            ("unrelated", valid), ("v=STSv1", valid),
            ("v=STSv1; id=1\nv=STSv1; id=2", valid),
            ("v=STSv1; id=1", "mode: enforce"),
            ("v=STSv1; id=1", valid + "\nmode: none"),
            ("v=stsv1; id=1", valid),
            ("v=STSv1; ID=1", valid),
            ("v=STSv1; id=1", valid.replace("version:", "VERSION:")),
            ("v=STSv1; id=1", valid.replace("*.example.test", "*bad.example.test")),
            ("v=STSv1; id=1", valid.replace("86400", "31557601")),
        ):
            with self.subTest(record=record, policy=policy):
                self.assertEqual(assess_mta_sts(record, parse_mta_sts_policy(policy))["assessment"], "UNKNOWN")
        self.assertEqual(assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy(valid))["assessment"], "SECURE")
        self.assertEqual(assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy(
            "version: STSv1\nmode: none\nmax_age: 0"))["assessment"], "INSECURE")
        self.assertEqual(assess_mta_sts("v=STSv1; id=1", parse_mta_sts_policy(
            valid.replace("86400", "0000086400")))["assessment"], "SECURE")


class EmailSampleTests(unittest.TestCase):
    def test_authentication_results_are_exact_and_ignore_comments(self):
        cases = (
            ("spf=passbad; dkim=passbad; dmarc=passbad", ("unknown", "unknown", "unknown")),
            ('spf=pass"invalid"; dkim=pass; dmarc=pass', ("unknown", "pass", "pass")),
            ("spf=fail (spf=pass); dkim=pass; dmarc=fail", ("fail", "pass", "fail")),
            ("spf=pass; spf=fail; dkim=pass", ("unknown", "pass", "unknown")),
            ("spf=temperror; dkim=pass header.d=example.test; dmarc=pass", ("temperror", "pass", "pass")),
        )
        for header, expected in cases:
            with self.subTest(header=header):
                data = f"Authentication-Results: mx.example.test; {header}\n\n".encode()
                with patch("builtins.open", side_effect=lambda *args, **kwargs: io.BytesIO(data)):
                    result = parse_eml_file("sample.eml")
                self.assertEqual(tuple(result[name] for name in ("spf", "dkim", "dmarc")), expected)


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
        with patch("email_audit.dns.lookup.dns.resolver.resolve") as resolve:
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
