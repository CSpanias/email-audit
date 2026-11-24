"""Generate the non-technical executive summary."""

from email_audit.dns.dkim import weak_dkim_keys
from email_audit.reporting.definitions import load_definitions

TEXT = load_definitions("narratives")["executive_summary"]


def build_executive_summary(domain, results, auth_results=None, spoof_result=None):
    """Summarise the assessment evidence and its business implications."""
    spf, dkim, dmarc, mta = results[:4]
    summary = [TEXT["introduction"].format(domain=domain)]

    controls_present = (
        spf["assessment"] != "MISSING"
        and dkim["assessment"] == "PRESENT"
        and dmarc["assessment"] != "MISSING"
    )
    authentication = (
        [auth_results.get(control) for control in ("spf", "dkim", "dmarc")]
        if auth_results else []
    )
    sample_passed = authentication and all(result == "pass" for result in authentication)
    if controls_present and sample_passed:
        evidence = [TEXT["controls_present_sample_passed"]]
    else:
        evidence = [TEXT["controls_present"] if controls_present else TEXT["controls_unconfirmed"]]
    if sample_passed:
        if not controls_present:
            evidence.append(TEXT["sample_passed"])
    elif "fail" in authentication:
        evidence.append(TEXT["sample_failed"])
    elif auth_results:
        evidence.append(TEXT["sample_incomplete"])
    else:
        evidence.append(TEXT["sample_not_supplied"])
    if dmarc["assessment"] == "INSECURE":
        evidence.append(TEXT["sender_protection_monitoring"])
    elif spf["assessment"] == "INSECURE":
        evidence.append(TEXT["sender_protection_weak"])
    elif any(control["assessment"] == "UNKNOWN" for control in (spf, dmarc)):
        evidence.append(TEXT["sender_protection_unconfirmed"])
    summary.append(" ".join(evidence))

    spoof_delivered = bool(spoof_result and spoof_result.get("successful"))
    if spoof_delivered:
        summary.append(TEXT["impersonation_delivered"].format(domain=domain))
    elif spoof_result:
        summary.append(TEXT["impersonation_not_delivered"])

    issues = []
    if mta["assessment"] == "MISSING":
        issues.append(TEXT["transport_missing"])
    elif mta["assessment"] in ("INSECURE", "ACCEPTABLE"):
        issues.append(TEXT["transport_not_enforced"])
    elif mta["assessment"] == "UNKNOWN":
        issues.append(TEXT["transport_unconfirmed"])

    if weak_dkim_keys(dkim):
        issues.append(TEXT["weak_signing_key"])

    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    if tls_rpt and tls_rpt["assessment"] == "MISSING":
        issues.append(TEXT["delivery_reporting_missing"])
    elif tls_rpt and tls_rpt["assessment"] == "INVALID":
        issues.append(TEXT["delivery_reporting_invalid"])
    elif tls_rpt and tls_rpt["assessment"] == "UNKNOWN":
        issues.append(TEXT["delivery_reporting_unconfirmed"])

    if issues:
        summary.append(" ".join([TEXT["additional_issues"]] + issues))

    if spoof_delivered:
        summary.append(TEXT["conclusion_impersonation"])
    elif (
        issues or not controls_present or "fail" in authentication
        or any(control["assessment"] in {"INSECURE", "UNKNOWN"} for control in (spf, dmarc))
    ):
        summary.append(TEXT["conclusion_improvements"])
    else:
        summary.append(TEXT["conclusion"])

    return "\n\n".join(summary)
