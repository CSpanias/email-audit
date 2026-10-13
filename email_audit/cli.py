"""
Command-line interface for Email-Audit.
"""

import argparse
import os

from email_audit.dns.spf import (
    assess_spf,
    get_spf_record,
)

from email_audit.dns.dkim import (
    assess_dkim,
    check_dkim_dns,
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

from email_audit.reporting.markdown import (
    export_markdown,
)

from email_audit.reporting.remediation import (
    build_recommendations,
)

from email_audit.output.console import (
    print_assessment,
    print_posture,
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
        description="Email security assessment tool"
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
            "Recipient address for spoofing test "
            "(default ceo@<domain>)"
        )
    )

    return parser.parse_args()


def process_email_sample(domain, email_file, results):
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

            results[1] = assess_dkim(
                dkim_selector,
                dkim_record,
                dkim_found,
                auth_results,
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

    print(
        f"\n[*] Retrieving DNS records and analysing email "
        f"controls for the {args.domain} domain...\n"
    )

    # -----------------------------------------------------------------------
    # DNS Retrieval
    # -----------------------------------------------------------------------
    spf_record = get_spf_record(args.domain)

    dkim_selector, dkim_record, dkim_found = (
        check_dkim_dns(args.domain)
    )

    dmarc_record = get_dmarc_record(args.domain)

    mta_record = check_mta_sts(args.domain)

    mta_policy_raw = get_mta_sts_policy(args.domain)

    mta_policy = parse_mta_sts_policy(
        mta_policy_raw
    )

    # -----------------------------------------------------------------------
    # Initial Assessment
    # -----------------------------------------------------------------------
    results = [
        assess_spf(spf_record),
        assess_dkim(
            dkim_selector,
            dkim_record,
            dkim_found,
            auth_results,
        ),
        assess_dmarc(dmarc_record),
        assess_mta_sts(
            mta_record,
            mta_policy,
        ),
    ]

    # --------------------------------------------------------------------------
    # Email Processing
    # --------------------------------------------------------------------------
    if args.email:
        auth_results = process_email_sample(
            args.domain,
            args.email,
            results,
        )

    # --------------------------------------------------------------------------
    # Assessment Output
    # --------------------------------------------------------------------------
    for result in results:
        print_assessment(result)

    print_posture(results)

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

    json_file = export_json(
        args.domain,
        findings,
    )

    md_file = export_markdown(
        args.domain,
        commentary,
        recommendations,
        results,
        auth_results,
    )

    # --------------------------------------------------------------------------
    # Completion Summary
    # --------------------------------------------------------------------------
    print_completion_summary(
        findings,
        json_file,
        md_file,
    )


if __name__ == "__main__":
    main()