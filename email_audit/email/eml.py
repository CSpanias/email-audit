"""
EML parsing and email authentication extraction.
"""

import re

from email import policy
from email.parser import BytesParser


# ---------------------------------------------------------------------------
# EML Parsing
# ---------------------------------------------------------------------------
def parse_eml_file(path):
    """
    Parse an EML file and extract authentication results.

    Extracts SPF, DKIM and DMARC authentication outcomes from the
    Authentication-Results header and attempts to identify the DKIM
    signing domain and selector from the DKIM-Signature header.
    """

    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "dkim_domain": "",
        "dkim_selector": ""
    }

    try:

        with open(path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        auth_results = str(msg.get("Authentication-Results", "")).lower()

        if "spf=pass" in auth_results:
            result["spf"] = "pass"

        elif "spf=fail" in auth_results:
            result["spf"] = "fail"

        elif "spf=temperror" in auth_results:
            result["spf"] = "temperror"

        else:
            result["spf"] = "unknown"

        if "dkim=pass" in auth_results:
            result["dkim"] = "pass"
        elif "dkim=fail" in auth_results:
            result["dkim"] = "fail"

        if "dmarc=pass" in auth_results:
            result["dmarc"] = "pass"
        elif "dmarc=fail" in auth_results:
            result["dmarc"] = "fail"

        dkim_sig = str(msg.get("DKIM-Signature", ""))
        domain_match = re.search(r"\bd=([^;\s]+)",dkim_sig,re.IGNORECASE)
        selector_match = re.search(r"\bs=([^;\s]+)",dkim_sig,re.IGNORECASE)

        if domain_match:
            result["dkim_domain"] = (domain_match.group(1))

        if selector_match:
            result["dkim_selector"] = (selector_match.group(1))

    except Exception as e:
        print(f"[!] Unable to parse EML: {e}")

    return result