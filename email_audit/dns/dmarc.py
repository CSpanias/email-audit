"""
DMARC record retrieval and assessment.
"""

from email_audit.dns.lookup import get_txt_records


# ---------------------------------------------------------------------------
# DNS Retrieval
# ---------------------------------------------------------------------------
def get_dmarc_record(domain):
    """
    Retrieve the DMARC record for a target domain.
    """

    for record in get_txt_records(f"_dmarc.{domain}"):
        if record.lower().split(";", 1)[0].strip() == "v=dmarc1":
            return record

    return ""


# ---------------------------------------------------------------------------
# DMARC Assessment
# ---------------------------------------------------------------------------
def assess_dmarc(record, dns_error=None):
    """
    Assess the security posture of a DMARC record.

    The record is parsed into individual DMARC tags and evaluated
    based on the configured enforcement policy. Additional reporting,
    alignment and subdomain settings are included within the assessment
    breakdown to support reporting and remediation activities.
    """

    result = {
        "control": "DMARC",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "",
    }

    if dns_error is not None:
        result["breakdown"].append(f"DNS lookup failed: {dns_error}")
        result["impact"] = "DMARC configuration could not be determined."
        result["assessment"] = "UNKNOWN"
        result["dns_error"] = dns_error
        return result

    if not record:

        result["breakdown"].append("No DMARC record present")
        result["impact"] = ("Receiving servers are not given any policy for handling authentication failures.")
        result["assessment"] = "MISSING"

        return result

    tags = {}
    duplicate_coverage_tags = set()

    for part in record.split(";"):

        part = part.strip()

        if "=" in part:
            k, v = part.split("=", 1)
            k, v = k.strip().lower(), v.strip()
            if k in tags and k in {"pct", "t"}:
                duplicate_coverage_tags.add(k)
            tags[k] = v

    policy = tags.get("p", "").lower()
    pct = tags.get("pct")
    testing = tags.get("t", "n").lower()
    coverage_errors = []
    if duplicate_coverage_tags:
        coverage_errors.append("Duplicate DMARC coverage tags: " + ", ".join(sorted(duplicate_coverage_tags)))
    if pct is not None and not (
        pct.isascii() and pct.isdecimal() and len(pct) <= 3 and int(pct) <= 100
    ):
        coverage_errors.append("Invalid DMARC pct value")
    if testing not in {"y", "n"}:
        coverage_errors.append("Invalid DMARC testing flag")
    limited = not coverage_errors and policy in {"reject", "quarantine"} and (
        (pct is not None and int(pct) < 100) or testing == "y"
    )
    result["tags"] = tags
    result["coverage_limited"] = limited
    result["coverage_errors"] = coverage_errors

    if "p" in tags:
        policy_text = {
            "reject": "Failed messages should be rejected",
            "quarantine": "Failed messages should be treated as suspicious",
            "none": "Monitoring only; no enforcement"
        }

        result["breakdown"].append(f"p={tags['p']} → {policy_text.get(tags['p'], '')}")

    if "pct" in tags:
        result["breakdown"].append(f"pct={tags['pct']} → Legacy policy sampling percentage")

    if "t" in tags:
        result["breakdown"].append(f"t={tags['t']} → DMARC policy testing flag")

    if "rua" in tags:
        result["breakdown"].append(f"rua={tags['rua']} → Aggregate DMARC reports destination")

    if "fo" in tags:
        result["breakdown"].append(f"fo={tags['fo']} → Defines when failure reports are generated")

    if "sp" in tags:
        result["breakdown"].append(f"sp={tags['sp']} → Policy applied to subdomains")

    if "adkim" in tags:
        mode = "Strict" if tags["adkim"] == "s" else "Relaxed"
        result["breakdown"].append(f"adkim={tags['adkim']} → {mode} DKIM alignment")

    if "aspf" in tags:
        mode = "Strict" if tags["aspf"] == "s" else "Relaxed"
        result["breakdown"].append(f"aspf={tags['aspf']} → {mode} SPF alignment")

    if limited:
        result["breakdown"].append("The published policy may be applied less restrictively by some recipients")
    result["breakdown"].extend(coverage_errors)

    if coverage_errors and policy in {"reject", "quarantine"}:
        result["impact"] = "The effective DMARC policy coverage could not be determined."
        result["assessment"] = "UNKNOWN"

    elif policy == "reject" and limited:
        result["impact"] = (
            "The published rejection policy may be applied less restrictively by some recipients."
        )
        result["assessment"] = "ACCEPTABLE"

    elif policy == "quarantine" and limited:
        result["impact"] = (
            "The published quarantine policy may be applied less restrictively by some recipients."
        )
        result["assessment"] = "INSECURE"

    elif policy == "reject":

        result["impact"] = ("Messages failing DMARC should be rejected.")
        result["assessment"] = "SECURE"

    elif policy == "quarantine":

        result["impact"] = ("Messages failing authentication should normally be treated as suspicious.")
        result["assessment"] = "ACCEPTABLE"

    elif policy == "none":

        result["impact"] = ("Authentication failures are monitored but not enforced.")
        result["assessment"] = "INSECURE"

    else:

        result["impact"] = ("Policy could not be clearly determined.")
        result["assessment"] = "UNKNOWN"

    return result