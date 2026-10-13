"""
DMARC record retrieval and assessment.
"""

from email_audit.utils import run_command


# ---------------------------------------------------------------------------
# DNS Retrieval
# ---------------------------------------------------------------------------
def get_dmarc_record(domain):
    """
    Retrieve the DMARC record for a target domain.
    """

    output = run_command(["dig", "+short", f"_dmarc.{domain}", "TXT"])

    for line in output.splitlines():

        if "v=DMARC1" in line:
            return line.strip('"')

    return ""


# ---------------------------------------------------------------------------
# DMARC Assessment
# ---------------------------------------------------------------------------
def assess_dmarc(record):
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
        "score": 0,
        "max_score": 3
    }

    if not record:

        result["breakdown"].append("No DMARC record present")
        result["impact"] = ("Receiving servers are not given any policy for handling authentication failures.")
        result["assessment"] = "MISSING"
        result["score"] = 0

        return result

    tags = {}

    for part in record.split(";"):

        part = part.strip()

        if "=" in part:
            k, v = part.split("=", 1)
            tags[k] = v

    if "p" in tags:
        policy_text = {
            "reject": "Failed messages should be rejected",
            "quarantine": "Failed messages should be treated as suspicious",
            "none": "Monitoring only; no enforcement"
        }

        result["breakdown"].append(f"p={tags['p']} → {policy_text.get(tags['p'], '')}")

    if "pct" in tags:
        result["breakdown"].append(f"pct={tags['pct']} → Policy applies to {tags['pct']}% of messages")

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

    policy = tags.get("p", "")

    if policy == "reject":

        result["impact"] = ("Messages failing SPF or DKIM should be rejected.")
        result["assessment"] = "SECURE"
        result["score"] = 3

    elif policy == "quarantine":

        result["impact"] = ("Messages failing authentication should normally be treated as suspicious.")
        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2

    elif policy == "none":

        result["impact"] = ("Authentication failures are monitored but not enforced.")
        result["assessment"] = "INSECURE"
        result["score"] = 0

    else:

        result["impact"] = ("Policy could not be clearly determined.")
        result["assessment"] = "UNKNOWN"
        result["score"] = 0

    result["tags"] = tags

    return result