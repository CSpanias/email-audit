"""
MTA-STS record retrieval, parsing and assessment.
"""

import re
import shlex
import urllib.request

from email_audit.dns.lookup import get_txt_records


class MtaStsPolicyError(Exception):
    """The HTTPS policy could not be retrieved or decoded."""


# ---------------------------------------------------------------------------
# DNS Retrieval
# ---------------------------------------------------------------------------
def check_mta_sts(domain):
    """
    Retrieve the MTA-STS DNS TXT record for a target domain.
    """

    return "\n".join(
        record for record in get_txt_records(f"_mta-sts.{domain}")
        if re.match(r"^v=STSv1(?:\s*;|\s*$)", record)
    )


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
    except (OSError, UnicodeError) as exc:
        raise MtaStsPolicyError(str(exc)) from exc


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
        "max_age": "",
        "errors": [],
    }

    if not policy:
        return result

    seen = set()
    for line in policy.splitlines():

        line = line.strip()

        if ":" not in line:
            result["errors"].append(f"Malformed policy line: {line}")
            continue

        key, value = line.split(":", 1)

        key = key.strip()
        value = value.strip()

        if key in {"version", "mode", "max_age"} and key in seen:
            result["errors"].append(f"Duplicate policy {key}")
        seen.add(key)
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
def assess_mta_sts(record, policy, dns_error=None, policy_error=None):
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
    }

    if dns_error is not None:
        result["breakdown"].append(f"DNS lookup failed: {dns_error}")
        result["impact"] = "MTA-STS configuration could not be determined."
        result["dns_error"] = dns_error
        return result

    if not record:

        result["breakdown"].append("No MTA-STS record present")
        result["impact"] = ("SMTP delivery may rely solely on opportunistic TLS.")
        result["assessment"] = "MISSING"

        return result

    if policy_error:
        result["policy_error"] = policy_error
        result["breakdown"].append(f"HTTPS policy lookup failed: {policy_error}")
        result["impact"] = "The MTA-STS policy could not be retrieved."
        return result

    result["policy"] = policy
    errors = list(policy.get("errors", []))
    records = record.splitlines()
    if len(records) != 1:
        errors.append("Multiple MTA-STS DNS records were identified")
    else:
        try:
            dns_record = "".join(shlex.split(records[0])) if records[0].lstrip().startswith('"') else records[0]
        except ValueError:
            dns_record = ""
        fields = [part.strip() for part in dns_record.split(";") if part.strip()]
        if not fields or fields[0] != "v=STSv1":
            errors.append("Invalid MTA-STS DNS version")
        ids = [part.partition("=")[2].strip() for part in fields[1:]
               if part.partition("=")[0].strip() == "id" and "=" in part]
        if len(ids) != 1 or not re.fullmatch(r"[A-Za-z0-9]{1,32}", ids[0]):
            errors.append("Missing, duplicated or invalid MTA-STS DNS id")

    if policy.get("version") != "STSv1":
        errors.append("Missing or invalid MTA-STS policy version")
    if policy.get("mode") not in {"enforce", "testing", "none"}:
        errors.append("Missing or invalid MTA-STS policy mode")
    max_age = policy.get("max_age", "")
    if (not max_age.isascii() or not max_age.isdecimal()
            or len(max_age) > 10 or int(max_age) > 31557600):
        errors.append("Missing or invalid MTA-STS policy max_age")
    mx_patterns = policy.get("mx", [])
    if policy.get("mode") in {"enforce", "testing"} and not mx_patterns:
        errors.append("MTA-STS policy requires at least one mx pattern")
    for mx in mx_patterns:
        hostname = mx[2:] if mx.startswith("*.") else mx
        labels = hostname.split(".")
        if not hostname or len(hostname) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            errors.append(f"Invalid MTA-STS mx pattern: {mx}")

    if errors:
        result["validation_errors"] = errors
        result["breakdown"].extend(errors)
        result["impact"] = "The MTA-STS DNS record or HTTPS policy could not be validated."
        return result

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

    elif mode == "testing":

        result["impact"] = ("TLS failures can be monitored, but the policy is not yet fully enforced.")
        result["assessment"] = "ACCEPTABLE"

    elif mode == "none":

        result["impact"] = ("MTA-STS is published but not enforced.")
        result["assessment"] = "INSECURE"

    else:

        result["impact"] = ("MTA-STS support is advertised, but the policy could not be retrieved or parsed successfully.")
        result["assessment"] = "UNKNOWN"

    return result