"""
SPF record retrieval and assessment.
"""

import ipaddress

from email_audit.dns.lookup import get_txt_records



# ---------------------------------------------------------------------------
# DNS Retrieval
# ---------------------------------------------------------------------------
def get_spf_record(domain):
    """
    Retrieve the SPF record for a target domain.
    """

    return "\n".join(
        record for record in get_txt_records(domain)
        if record.lower().split()[:1] == ["v=spf1"]
    )


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

    if len(record.splitlines()) != 1:
        result["breakdown"].append("Multiple SPF records were identified")
        result["impact"] = "Multiple SPF records cause SPF processing to fail."
        result["assessment"] = "UNKNOWN"
        result["record_error"] = "multiple SPF records"
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

    broad_mechanism = None
    blocked_families = set()
    for element in elements[1:]:
        if element.lower() in ("all", "+all", "-all", "~all", "?all"):
            break
        term = element[1:] if element.startswith(("+", "-", "~", "?")) else element
        if term.lower().startswith(("ip4:", "ip6:")):
            family, value = term.split(":", 1)
            try:
                if "/" in value:
                    prefix = value.rsplit("/", 1)[1]
                    if not prefix.isascii() or not prefix.isdecimal():
                        raise ValueError("Invalid SPF prefix length")
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                network = None
            if network is None or network.version != (4 if family.lower() == "ip4" else 6):
                result["record_error"] = f"invalid IP mechanism {element}"
                result["breakdown"].append(f"Invalid SPF IP mechanism: {element}")
                result["impact"] = "The SPF configuration could not be determined."
                result["assessment"] = "UNKNOWN"
                return result
            if network.prefixlen == 0:
                if element.startswith(("-", "~", "?")):
                    blocked_families.add(network.version)
                elif network.version not in blocked_families:
                    broad_mechanism = (element, network.version)

    if broad_mechanism:
        element, version = broad_mechanism
        result["broad_mechanism"] = element
        result["breakdown"].append(f"{element} can permit a broad range of IPv{version} senders")
        result["impact"] = f"The SPF record can permit a broad range of IPv{version} senders."
        result["assessment"] = "INSECURE"
        return result

    if all_policy == "-all":

        result["impact"] = (
            "Senders not matched earlier receive an SPF fail result; recipients decide how to handle it."
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