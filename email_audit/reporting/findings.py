"""
Assessment findings generation and JSON export.
"""

import json

from email_audit.constants import FINDING_MAP


# ---------------------------------------------------------------------------
# Findings Generation
# ---------------------------------------------------------------------------

def build_findings(
    domain,
    results,
    auth_results=None,
    spoof_result=None,
):
    """
    Generate assessment findings from control assessments.

    Converts assessment outcomes into generic findings that can be
    exported and consumed by downstream reporting platforms.
    """

    findings = [{
        "id": "email-audit",
        "description":
            f"Email security controls were reviewed for {domain}, including "
            "SPF, DKIM, DMARC and MTA-STS."
    }]

    checks = [
        ("SPF", results[0]["assessment"]),
        ("DKIM", results[1]["assessment"]),
        ("DMARC", results[2]["assessment"]),
        ("MTA-STS", results[3]["assessment"])
    ]

    for control, assessment in checks:

        key = (control, assessment)

        if key not in FINDING_MAP:
            continue

        findings.append({
            "id": FINDING_MAP[key]["id"],
            "description": (
                FINDING_MAP[key]["description"].format(domain=domain)
            )
        })

    # -----------------------------------------------------------------------
    # Authentication Validation Findings
    # -----------------------------------------------------------------------

    if auth_results:

        if auth_results.get("spf") == "temperror":

            findings.append({
                "id": "spf-processing-failure",
                "description": (
                    "SPF authentication could not be completed successfully "
                    "during testing due to a temporary processing error."
                )
            })

    if spoof_result:

        if spoof_result.get("successful"):

            findings.append({
                "id": "email-spoofing-possible",
                "description": (
                    "A controlled spoofing assessment demonstrated "
                    "that an email claiming to originate from the "
                    "target domain was successfully delivered."
                )
            })

    return findings

# ---------------------------------------------------------------------------
# JSON Export
# ---------------------------------------------------------------------------

def export_json(domain, findings):
    """
    Export assessment findings to JSON format.
    """

    filename = f"{domain}.json"

    with open(filename, "w", encoding="utf-8") as handle:

        json.dump(
            {
                "tool": "email-audit",
                "domain": domain,
                "findings": findings
            },
            handle,
            indent=4
        )

    return filename