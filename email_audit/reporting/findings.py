"""
Assessment findings generation and JSON export.
"""

import json

from email_audit.dns.dkim import weak_dkim_keys
from email_audit.reporting.definitions import load_definitions

FINDING_GATES = {
    ("SPF", "MISSING"): "missing-spf",
    ("DKIM", "UNKNOWN"): "missing-dkim",
    ("DMARC", "MISSING"): "missing-dmarc",
    ("MTA-STS", "MISSING"): "missing-mta-sts",
    ("MTA-STS", "UNKNOWN"): "invalid-mta-sts",
}


def _finding(finding_id, domain, **values):
    definition = load_definitions("findings")[finding_id]
    return {
        "id": finding_id,
        "description": definition["description"].format(domain=domain, **values),
    }


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

    findings = [_finding("email-audit", domain)]

    checks = [
        ("SPF", results[0]["assessment"]),
        ("DKIM", results[1]["assessment"]),
        ("DMARC", results[2]["assessment"]),
        ("MTA-STS", results[3]["assessment"])
    ]

    for control, assessment in checks:

        key = (control, assessment)

        if key not in FINDING_GATES:
            continue

        result = next(item for item in results if item["control"] == control)
        if result.get("dns_error") or result.get("dns_errors"):
            continue
        if control == "DKIM" and result.get("raw"):
            continue

        findings.append(_finding(FINDING_GATES[key], domain))

    spf, dkim, dmarc, mta = results[:4]
    if spf.get("broad_mechanism"):
        findings.append(_finding("broad-spf", domain, mechanism=spf["broad_mechanism"]))
    elif spf["assessment"] == "INSECURE":
        findings.append(_finding("permissive-spf", domain))
    if spf.get("record_error"):
        findings.append(_finding("invalid-spf", domain, reason=spf["record_error"]))

    observations = dkim.get("key_observations", [dkim])
    for key in observations:
        if key.get("key_assessment") == "UNKNOWN" and key.get("raw", True) and key.get("selector"):
            findings.append(_finding("unconfirmed-dkim-key", domain, selector=key["selector"]))
    if dmarc.get("record_errors") or dmarc.get("coverage_errors"):
        findings.append(_finding("invalid-dmarc", domain))
    if dmarc.get("coverage_limited"):
        findings.append(_finding("limited-dmarc", domain))
    elif not dmarc.get("record_errors") and dmarc.get("tags", {}).get("p", "").lower() == "none":
        findings.append(_finding("monitoring-dmarc", domain))
    if mta["assessment"] in {"INSECURE", "ACCEPTABLE"}:
        findings.append(_finding("non-enforcing-mta-sts", domain, mode=mta["policy"]["mode"]))

    for dkim in weak_dkim_keys(results[1]):
        findings.append(_finding(
            "weak-dkim-rsa-key", domain, selector=dkim["selector"], bits=dkim["key_bits"]
        ))

    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    if tls_rpt and tls_rpt["assessment"] == "MISSING":
        findings.append(_finding("missing-tls-rpt", domain))
    elif tls_rpt and tls_rpt["assessment"] == "INVALID":
        findings.append(_finding("invalid-tls-rpt", domain, reason=tls_rpt["breakdown"][0]))

    # -----------------------------------------------------------------------
    # Authentication Validation Findings
    # -----------------------------------------------------------------------

    if auth_results:

        if auth_results.get("spf") == "temperror":

            findings.append(_finding("spf-processing-failure", domain))

    if spoof_result:

        if spoof_result.get("successful"):

            findings.append(_finding("email-spoofing-possible", domain))

    return findings

# ---------------------------------------------------------------------------
# JSON Export
# ---------------------------------------------------------------------------

def export_json(domain, findings, filename=None):
    """
    Export assessment findings to JSON format.
    """

    if filename is None:
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