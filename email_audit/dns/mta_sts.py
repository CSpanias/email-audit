"""
MTA-STS record retrieval, parsing and assessment.
"""

import urllib.request

from email_audit.utils import run_command


# ---------------------------------------------------------------------------
# DNS Retrieval
# ---------------------------------------------------------------------------
def check_mta_sts(domain):
    """
    Retrieve the MTA-STS DNS TXT record for a target domain.
    """

    output = run_command(["dig", "+short", f"_mta-sts.{domain}", "TXT"])
    
    return output.strip()


# ---------------------------------------------------------------------------
# Policy Retrieval
# ---------------------------------------------------------------------------
def get_mta_sts_policy(domain):
    """
    Retrieve the MTA-STS policy file from the well-known HTTPS endpoint.
    """

    url = (f"https://mta-sts.{domain}/.well-known/mta-sts.txt")

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return (
                response.read()
                .decode()
                .strip()
            )
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Policy Parsing
# ---------------------------------------------------------------------------
def parse_mta_sts_policy(policy):
    """
    Parse an MTA-STS policy into a structured dictionary.

    Extracts policy version, enforcement mode, authorised
    mail servers and cache duration values.
    """

    result = {
        "version": "",
        "mode": "",
        "mx": [],
        "max_age": ""
    }

    if not policy:
        return result

    for line in policy.splitlines():

        line = line.strip()

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        key = key.strip().lower()
        value = value.strip()

        if key == "version":
            result["version"] = value

        elif key == "mode":
            result["mode"] = value

        elif key == "mx":
            result["mx"].append(value)

        elif key == "max_age":
            result["max_age"] = value

    return result


# ---------------------------------------------------------------------------
# MTA-STS Assessment
# ---------------------------------------------------------------------------
def assess_mta_sts(record, policy):
    """
    Assess the security posture of an MTA-STS deployment.

    The assessment evaluates the published DNS record and
    associated HTTPS policy to determine the effectiveness
    of SMTP transport security controls.
    """

    result = {
        "control": "MTA-STS",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "UNKNOWN",
        "score": 0,
        "max_score": 3
    }

    if not record:

        result["breakdown"].append("No MTA-STS record present")
        result["impact"] = ("SMTP delivery may rely solely on opportunistic TLS.")
        result["assessment"] = "MISSING"

        return result

    # DNS record exists
    result["breakdown"].append("Domain advertises support for MTA-STS")

    if policy["version"]:
        result["breakdown"].append(f"version={policy['version']} → Policy version")

    if policy["mode"]:
        result["breakdown"].append(f"mode={policy['mode']} → Enforcement mode")

    for mx in policy["mx"]:
        result["breakdown"].append(f"mx={mx} → Authorised mail server")

    if policy["max_age"]:
        result["breakdown"].append(f"max_age={policy['max_age']} → Policy cache duration")

    mode = policy.get("mode", "")

    if mode == "enforce":
        result["impact"] = ("Compatible mail servers should only deliver email over validated TLS connections.")
        result["assessment"] = "SECURE"
        result["score"] = 3

    elif mode == "testing":

        result["impact"] = ("TLS failures can be monitored, but the policy is not yet fully enforced.")
        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2

    elif mode == "none":

        result["impact"] = ("MTA-STS is published but not enforced.")
        result["assessment"] = "INSECURE"
        result["score"] = 0

    else:

        result["impact"] = ("MTA-STS support is advertised, but the policy could not be retrieved or parsed successfully.")
        result["assessment"] = "UNKNOWN"
        result["score"] = 1

    result["policy"] = policy

    return result