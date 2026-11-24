"""
SPF record retrieval and assessment.
"""

from email_audit.utils import run_command



# ---------------------------------------------------------------------------
# DNS Retrieval
# ---------------------------------------------------------------------------
def get_spf_record(domain):
    """
    Retrieve the SPF record for a target domain.
    """

    output = run_command(["dig", "+short", domain, "TXT"])

    for line in output.splitlines():

        if "v=spf1" in line:
            return line.strip('"')

    return ""


# ---------------------------------------------------------------------------
# SPF Assessment
# ---------------------------------------------------------------------------
def assess_spf(record):
    """
    Assess the security posture of an SPF record.
    """

    result = {
        "control": "SPF",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "",
    }

    if not record:

        result["breakdown"].append("No SPF record present")
        result["impact"] = (
            "Receiving systems cannot determine which mail servers are "
            "authorised to send email."
        )
        result["assessment"] = "MISSING"

        return result

    elements = record.split()

    for element in elements:

        if element.startswith("include:"):
            result["breakdown"].append(
                f"{element} → Authorised third-party provider"
            )

        elif element.startswith("ip4:"):
            result["breakdown"].append(
                f"{element} → Authorised IPv4 sender"
            )

        elif element.startswith("ip6:"):
            result["breakdown"].append(
                f"{element} → Authorised IPv6 sender"
            )

        elif element.endswith("all"):
            result["breakdown"].append(
                f"{element} → SPF enforcement policy"
            )

    if "-all" in elements:

        result["impact"] = (
            "Unauthorised sending mail servers should be rejected."
        )
        result["assessment"] = "SECURE"

    elif "~all" in elements:

        result["impact"] = (
            "Unauthorised senders may still be accepted by some recipients."
        )
        result["assessment"] = "ACCEPTABLE"

    elif "+all" in elements:

        result["impact"] = (
            "Any sender is effectively authorised to send email."
        )
        result["assessment"] = "INSECURE"

    else:

        result["impact"] = (
            "SPF enforcement behaviour could not be clearly determined."
        )
        result["assessment"] = "UNKNOWN"

    return result