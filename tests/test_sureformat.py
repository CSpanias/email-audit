import contextlib
import io
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from email_audit import cli
from email_audit.reporting.sureformat import export_sureformat


class SureFormatTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(os.chdir, self.old_cwd)

    def test_xml_mapping_escaping_and_unmapped_warning(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            filename, count = export_sureformat("example.test", [
                {"id": "email-audit", "description": "Review <mail> & DNS"},
                {"id": "missing-spf", "description": "No SPF"},
                {"id": "unknown", "description": "Not exported"},
            ])

        root = ET.parse(filename).getroot()
        item = root.find("item")
        service = item.find("./services/service")
        findings = service.findall("./vulnerabilities/vulnerability")
        self.assertEqual(root.attrib, {"source": "SureFormat", "version": "1.0.0"})
        self.assertEqual(item.attrib, {"ipaddress": "", "hostname": "example.test"})
        self.assertEqual(service.attrib, {"name": "", "port": "", "protocol": "tcp"})
        self.assertEqual([f.attrib["id"] for f in findings], ["SC-2157", "SC-2090"])
        self.assertEqual(findings[0].findtext("information"), "Review <mail> & DNS")
        self.assertEqual(count, 2)
        self.assertIn("unknown", output.getvalue())

    def test_cli_writes_selected_export_and_keeps_html(self):
        findings = [
            {"id": "email-audit", "description": "Review"},
            {"id": "unmapped", "description": "Omitted from XML"},
        ]
        for flag in (False, True):
            with self.subTest(csacyber=flag), contextlib.ExitStack() as stack:
                args = ["email-audit", "example.test"] + (["--csacyber"] if flag else [])
                stack.enter_context(patch("sys.argv", args))
                for name in (
                    "get_spf_record", "get_dmarc_record", "check_mta_sts",
                    "get_mta_sts_policy", "parse_mta_sts_policy", "assess_spf",
                    "assess_dkim_records", "assess_dmarc", "assess_mta_sts",
                    "print_assessment", "build_commentary",
                    "build_recommendations",
                ):
                    stack.enter_context(patch.object(cli, name))
                stack.enter_context(
                    patch.object(cli, "check_dkim_selectors", return_value=[])
                )
                stack.enter_context(patch.object(cli, "get_tls_rpt_records", return_value=([], None)))
                stack.enter_context(patch.object(cli, "build_findings", return_value=findings))
                html = stack.enter_context(
                    patch.object(cli, "export_html", return_value="x.html")
                )
                summary = stack.enter_context(patch.object(cli, "print_completion_summary"))

                cli.main()

                html.assert_called_once()
                self.assertEqual(
                    summary.call_args.kwargs["output_format"], "XML" if flag else "JSON"
                )
                if flag:
                    self.assertTrue(os.path.isfile("example.test.xml"))
                    self.assertEqual(summary.call_args.kwargs["exported_count"], 1)
                    with open("example.test.json", encoding="utf-8") as file:
                        self.assertEqual(json.load(file)["findings"], findings)
                else:
                    self.assertFalse(os.path.exists("example.test.xml"))
                    with open("example.test.json", encoding="utf-8") as file:
                        self.assertEqual(json.load(file)["findings"], findings)


if __name__ == "__main__":
    unittest.main()
