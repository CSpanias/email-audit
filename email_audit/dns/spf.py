"""
SPF record retrieval and assessment.
"""

from email_audit.dns.lookup import get_txt_records



# ---------------------------------------------------------------------------
# DNS Retrieval
# ---------------------------------------------------------------------------
def get_spf_record(domain):
    """
    Retrieve the SPF record for a target domain.
    """

    for record in get_txt_records(domain):
        if record.lower().split()[:1] == ["v=spf1"]:
            return record

    return ""


# ---------------------------------------------------------------------------
# SPF Assessment
# ---------------------------------------------------------------------------
def assess_spf(record, dns_error=None):
    """
    Assess the security posture of an SPF record.
    """

    result = {
        "control": "SPF",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "",
        "all_policy": "",
    }

    if dns_error is not None:
        result["breakdown"].append(f"DNS lookup failed: {dns_error}")
        result["impact"] = "SPF configuration could not be determined."
        result["assessment"] = "UNKNOWN"
        result["dns_error"] = dns_error
        return result

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

        elif element.lower() in ("all", "+all", "-all", "~all", "?all"):
            result["breakdown"].append(
                f"{element} → SPF enforcement policy"
            )

    all_policy = next((element.lower() for element in elements[1:]
                       if element.lower() in ("all", "+all", "-all", "~all", "?all")), "")
    result["all_policy"] = all_policy

    if all_policy == "-all":

        result["impact"] = (
            "Unauthorised sending mail servers should be rejected."
        )
        result["assessment"] = "SECURE"

    elif all_policy == "~all":

        result["impact"] = (
            "Unauthorised senders may still be accepted by some recipients."
        )
        result["assessment"] = "ACCEPTABLE"

    elif all_policy in ("all", "+all"):

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