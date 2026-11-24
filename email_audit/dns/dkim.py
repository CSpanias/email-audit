"""
DKIM record discovery and assessment.
"""

import base64
import binascii
import re
import shlex

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from email_audit.constants import COMMON_DKIM_SELECTORS
from email_audit.dns.lookup import DNSLookupError, get_txt_records


def assess_dkim_key(record):
    """Assess the RSA size of a discovered DNS key, without guessing on errors."""
    for line in record.splitlines():
        try:
            text = "".join(shlex.split(line)) if line.lstrip().startswith('"') else line
        except ValueError:
            return "UNKNOWN", None, "DKIM record could not be parsed"
        if "v=DKIM1" in text:
            break
    else:
        return "UNKNOWN", None, "DKIM key record could not be identified"

    tags = {}
    for field in text.split(";"):
        if "=" not in field:
            continue
        key, value = field.strip().split("=", 1)
        key = key.strip().lower()
        if key in tags:
            return "UNKNOWN", None, "DKIM key record has duplicate tags"
        tags[key] = value.strip()
    encoded = re.sub(r"\s+", "", tags.get("p", ""))
    if not encoded:
        return "UNKNOWN", None, "DKIM public key is empty or missing"
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return "UNKNOWN", None, "DKIM public key could not be decoded"
    algorithm = tags.get("k", "rsa").lower()
    if algorithm == "ed25519":
        if len(decoded) != 32:
            return "UNKNOWN", None, "DKIM Ed25519 public key must be 32 bytes"
        return "NOT APPLICABLE", None, "DKIM Ed25519 public key is present"
    if algorithm != "rsa":
        return "UNKNOWN", None, f"Unsupported DKIM public key algorithm: {algorithm}"
    try:
        key = load_der_public_key(decoded)
    except (ValueError, binascii.Error, UnsupportedAlgorithm):
        return "UNKNOWN", None, "DKIM RSA public key could not be decoded"
    if not isinstance(key, RSAPublicKey):
        return "UNKNOWN", None, "DKIM public key is not a valid RSA key"
    bits = key.key_size
    if bits < 2048:
        return "WEAK", bits, f"RSA public key: {bits} bits (below 2048 bits)"
    return "ADEQUATE", bits, f"RSA public key: {bits} bits"


# ---------------------------------------------------------------------------
# DKIM Discovery
# ---------------------------------------------------------------------------
def check_dkim_dns(domain, selector=None):
    """
    Discover and validate a DKIM selector through DNS.

    If a selector is supplied, that selector is queried directly.
    Otherwise, a set of commonly used selectors is tested to
    identify a valid DKIM record.
    """

    # Common selectors
    selectors = ([selector] if selector else COMMON_DKIM_SELECTORS)

    for selector in selectors:

        output = "\n".join(get_txt_records(f"{selector}._domainkey.{domain}"))

        if not output:
            continue

        # Valid DKIM record
        if "v=DKIM1" in output:
            return selector, output, True

        return selector, output, False

    return "", "", False


def check_dkim_selectors(domain, errors=None):
    """Query every common selector and retain each non-empty response."""
    records = []
    for selector in COMMON_DKIM_SELECTORS:
        try:
            found_selector, record, found = check_dkim_dns(domain, selector)
        except DNSLookupError as exc:
            if errors is None:
                raise
            errors.append(str(exc))
            continue
        if record:
            records.append((found_selector, record, found))
    return records


def assess_dkim_records(records, auth_results=None, selected=None, dns_errors=None):
    """Assess the primary selector while retaining evidence from all discovered keys."""
    candidates = ([selected] if selected and selected[1] else []) + list(records)
    primary = next(
        (item for item in candidates if item[2] and assess_dkim_key(item[1])[0] != "UNKNOWN"),
        candidates[0] if candidates else ("", "", False),
    )
    result = assess_dkim(*primary, auth_results)
    if dns_errors:
        result["dns_errors"] = list(dns_errors)
        if not primary[1]:
            result["breakdown"] = ["DKIM selector discovery was incomplete"]
        result["breakdown"].extend(f"DNS lookup failed: {error}" for error in dns_errors)
    observations = []
    by_selector = {selector: (selector, record, found) for selector, record, found in records}
    if selected and selected[1] and (selected[2] or selected[0] not in by_selector):
        by_selector[selected[0]] = selected
    for selector, record, found in by_selector.values():
        if not found:
            continue
        assessment, bits, message = assess_dkim_key(record)
        observations.append({
            "selector": selector, "key_assessment": assessment, "key_bits": bits,
            "message": message,
        })
        if selector != primary[0]:
            result["breakdown"].append(f"Selector {selector}: {message}")
    result["key_observations"] = observations
    return result


def weak_dkim_keys(result):
    observations = result.get("key_observations", [result])
    return [item for item in observations if item.get("key_assessment") == "WEAK"]


# ---------------------------------------------------------------------------
# DKIM Assessment
# ---------------------------------------------------------------------------
def assess_dkim(selector, record, dkim_found, auth_results=None):
    """
    Assess the presence and effectiveness of a DKIM deployment.

    The assessment validates that a DKIM selector and corresponding
    public key are published in DNS and, where available, incorporates
    DKIM authentication results extracted from a supplied email sample.
    """
    
    result = {
        "control": "DKIM",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "",
        "selector": selector,
        "key_assessment": "UNKNOWN",
        "key_bits": None,
    }

    if not record:

        result["breakdown"].append("No common selector detected")
        result["impact"] = ("DKIM support could not be confirmed through DNS.")
        result["assessment"] = "UNKNOWN"

        return result
    
    if selector in COMMON_DKIM_SELECTORS:
        result["breakdown"].append(f"Common selector discovered: {selector}")
    else:
        result["breakdown"].append(f"Selector extracted from supplied email: {selector}")
        
    if dkim_found:

        key_assessment, key_bits, key_message = assess_dkim_key(record)
        result["key_assessment"] = key_assessment
        result["key_bits"] = key_bits
        result["breakdown"].append(key_message)

        if key_assessment == "UNKNOWN":
            result["key_error"] = key_message
            result["impact"] = "The discovered DKIM public key could not be validated."
            result["assessment"] = "UNKNOWN"
            return result

        result["breakdown"].append("Public key present in DNS")
        if auth_results and auth_results.get("dkim", "").lower() == "pass":

            result["impact"] = ("The domain supports DKIM signature validation and "
                                "DKIM was observed to be functioning correctly within the supplied email sample.")

        elif auth_results and auth_results.get("dkim", "").lower() == "fail":

            result["impact"] = ("The domain supports DKIM signature validation; however, DKIM authentication failed within the supplied email sample.")

        else:

            result["impact"] = ("The domain supports DKIM signature validation. Actual implementation still requires inspection of a received email.")

        result["assessment"] = "PRESENT"

    else:

        result["breakdown"].append("Selector delegation identified")
        result["breakdown"].append("No DKIM public key could be confirmed")
        result["impact"] = ("A DKIM selector was identified, however a corresponding DKIM public key could not be verified automatically.")
        result["assessment"] = "UNKNOWN"

    return result