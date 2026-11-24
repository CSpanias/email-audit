"""
Command-line interface for Email-Audit.
"""

import argparse
import os
from datetime import datetime
from pathlib import Path
from textwrap import dedent

from rich_argparse import RawDescriptionRichHelpFormatter
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

from email_audit.dns.spf import (
    assess_spf,
    get_spf_record,
)

from email_audit.dns.dkim import (
    assess_dkim_records,
    check_dkim_dns,
    check_dkim_selectors,
)

from email_audit.dns.dmarc import (
    assess_dmarc,
    get_dmarc_record,
)

from email_audit.dns.mta_sts import (
    assess_mta_sts,
    check_mta_sts,
    get_mta_sts_policy,
    parse_mta_sts_policy,
)

from email_audit.dns.tls_rpt import assess_tls_rpt, get_tls_rpt_records

from email_audit.email.eml import (
    parse_eml_file,
)

from email_audit.email.msg import (
    convert_msg_to_eml,
)

from email_audit.reporting.commentary import (
    build_commentary,
)

from email_audit.reporting.findings import (
    build_findings,
    export_json,
)

from email_audit.reporting.html import export_html

from email_audit.reporting.sureformat import export_sureformat

from email_audit.reporting.remediation import (
    build_recommendations,
)

from email_audit.output.console import (
    console,
    print_info,
    print_assessment,
    print_section,
    print_completion_summary,
)

from email_audit.output.evidence import (
    report_authentication_validation,
    report_configuration_validation,
)

from email_audit.spoofing.spoof import (
    perform_spoof_test,
    report_spoof,
)


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="Assess email authentication and transport security controls.",
        formatter_class=RawDescriptionRichHelpFormatter,
        epilog=dedent("""\
            Examples:
              email-audit example.com
              email-audit example.com --email sample.eml
              email-audit example.com --spoof recipient@example.com
              email-audit example.com --csacyber
        """),
    )

    parser.add_argument(
        "domain",
        help="Target domain"
    )

    parser.add_argument(
        "-E",
        "--email",
        help="Path to EML or MSG file"
    )

    parser.add_argument(
        "--spoof",
        metavar="EMAIL",
        help=(
            "Recipient address for a controlled spoofing test "
            "(sender: ceo@<domain>)"
        )
    )

    parser.add_argument(
        "--csacyber",
        action="store_true",
        help="Export SureFormat XML instead of JSON findings",
    )

    return parser.parse_args()


def process_email_sample(domain, email_file, results, dkim_records):
    """
    Parse a supplied email sample and update assessment results.
    """

    temp_eml = None

    try:

        if email_file.lower().endswith(".msg"):
            temp_eml = convert_msg_to_eml(email_file)
            email_file = temp_eml

        auth_results = parse_eml_file(email_file)

        if auth_results["dkim_selector"]:

            dkim_selector, dkim_record, dkim_found = (
                check_dkim_dns(
                    domain,
                    auth_results["dkim_selector"],
                )
            )

            results[1] = assess_dkim_records(
                dkim_records, auth_results, (dkim_selector, dkim_record, dkim_found)
            )

        return auth_results

    finally:

        if temp_eml and os.path.exists(temp_eml):
            os.remove(temp_eml)


def main():
    """
    Execute an email security assessment.

    Handles argument parsing, assessment orchestration,
    evidence generation and report export.
    """

    auth_results = None
    spoof_result = None

    args = parse_arguments()

    console.print()
    print_info(
        f"Retrieving DNS records and analysing email controls for the {args.domain} domain..."
    )

    # -----------------------------------------------------------------------
    # DNS Retrieval
    # -----------------------------------------------------------------------
    with Progress(
        TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(),
        TimeElapsedColumn(), console=console, transient=True, disable=not console.is_terminal,
    ) as progress:
        task = progress.add_task("Checking SPF", total=5)
        spf_record = get_spf_record(args.domain)
        progress.update(task, advance=1, description="Checking DKIM", refresh=True)
        dkim_records = check_dkim_selectors(args.domain)
        progress.update(task, advance=1, description="Checking DMARC", refresh=True)
        dmarc_record = get_dmarc_record(args.domain)
        progress.update(task, advance=1, description="Checking MTA-STS", refresh=True)
        mta_record = check_mta_sts(args.domain)
        mta_policy_raw = get_mta_sts_policy(args.domain)
        mta_policy = parse_mta_sts_policy(mta_policy_raw)
        progress.update(task, advance=1, description="Checking TLS-RPT", refresh=True)
        tls_rpt_records, tls_rpt_error = get_tls_rpt_records(args.domain)
        progress.update(task, advance=1, description="DNS checks complete", refresh=True)

    # -----------------------------------------------------------------------
    # Initial Assessment
    # -----------------------------------------------------------------------
    results = [
        assess_spf(spf_record),
        assess_dkim_records(dkim_records, auth_results),
        assess_dmarc(dmarc_record),
        assess_mta_sts(
            mta_record,
            mta_policy,
        ),
        assess_tls_rpt(tls_rpt_records, tls_rpt_error),
    ]

    # --------------------------------------------------------------------------
    # Email Processing
    # --------------------------------------------------------------------------
    if args.email:
        auth_results = process_email_sample(
            args.domain,
            args.email,
            results,
            dkim_records,
        )

    # --------------------------------------------------------------------------
    # Assessment Output
    # --------------------------------------------------------------------------
    for result in results:
        print_assessment(result)

    if auth_results:
        print_section("SCREENSHOT EVIDENCE")
        report_configuration_validation(results)
        print()
        report_authentication_validation(auth_results)

    if args.spoof:

        spoof_result = perform_spoof_test(
            args.domain,
            args.spoof,
        )

        report_spoof(spoof_result)

        delivered = input(
            "\n[?] Was the spoofed email successfully delivered? [y/N]: "
        ).strip().lower()

        spoof_result["successful"] = delivered == "y"

    # -----------------------------------------------------------------------
    # Generate Findings
    # -----------------------------------------------------------------------
    findings = build_findings(
        args.domain,
        results,
        auth_results,
        spoof_result,
    )


    # -----------------------------------------------------------------------
    # Export Reports
    # -----------------------------------------------------------------------
    commentary = build_commentary(
        args.domain,
        results,
        auth_results,
        spoof_result,
    )

    recommendations = build_recommendations(
        results,
        auth_results,
        spoof_result,
    )

    output_dir = Path("email-audit")
    output_dir.mkdir(exist_ok=True)
    prefix = output_dir / f"{args.domain}-{datetime.now():%Y%m%d-%H%M%S-%f}"

    if args.csacyber:
        findings_file, exported_count = export_sureformat(
            args.domain, findings, filename=f"{prefix}.xml"
        )
    else:
        findings_file = export_json(args.domain, findings, filename=f"{prefix}.json")
        exported_count = len(findings)

    html_file = export_html(
        args.domain,
        commentary,
        recommendations,
        results,
        findings,
        auth_results,
        spoof_result,
        filename=f"{prefix}.html",
    )

    # --------------------------------------------------------------------------
    # Completion Summary
    # --------------------------------------------------------------------------
    print_completion_summary(
        findings,
        findings_file,
        html_file,
        output_format="XML" if args.csacyber else "JSON",
        exported_count=exported_count,
    )


if __name__ == "__main__":
    main()