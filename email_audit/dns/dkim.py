"""
DKIM record discovery and assessment.
"""

from email_audit.constants import COMMON_DKIM_SELECTORS
from email_audit.utils import run_command


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

        output = run_command([
            "dig",
            "+short",
            f"{selector}._domainkey.{domain}",
            "TXT"
        ])

        if not output:
            continue

        # Valid DKIM record
        if "v=DKIM1" in output:
            return selector, output, True

        # If output returned, but not DKIM record -> possible CNAME target
        target = output.strip().rstrip(".")
        dkim_record = run_command(["dig", "+short", target, "TXT"])

        if "v=DKIM1" in dkim_record:
            return selector, dkim_record, True

        return selector, output, False

    return "", "", False


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
        "score": 0,
        "max_score": 1
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

        result["breakdown"].append("Public key present in DNS")

        if auth_results and auth_results.get("dkim", "").lower() == "pass":

            result["impact"] = ("The domain supports DKIM signature validation and "
                                "DKIM was observed to be functioning correctly within the supplied email sample.")

        elif auth_results and auth_results.get("dkim", "").lower() == "fail":

            result["impact"] = ("The domain supports DKIM signature validation; however, DKIM authentication failed within the supplied email sample.")

        else:

            result["impact"] = ("The domain supports DKIM signature validation. Actual implementation still requires inspection of a received email.")

        result["assessment"] = "PRESENT"
        result["score"] = 1

    else:

        result["breakdown"].append("Selector delegation identified")
        result["breakdown"].append("No DKIM public key could be confirmed")
        result["impact"] = ("A DKIM selector was identified, however a corresponding DKIM public key could not be verified automatically.")
        result["assessment"] = "UNKNOWN"

    return result