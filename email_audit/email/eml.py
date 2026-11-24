"""
EML parsing and email authentication extraction.
"""

import re

from email import policy
from email.parser import BytesParser


def _authentication_results(header):
    """Extract unambiguous method results outside comments and quoted strings."""
    parts = []
    current = []
    depth = 0
    quoted = False
    escaped = False
    for char in header:
        if escaped:
            escaped = False
            continue
        if char == "\\" and (quoted or depth):
            escaped = True
        elif depth:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
        elif quoted:
            if char == '"':
                quoted = False
        elif char == "(":
            depth = 1
            current.append(" ")
        elif char == '"':
            quoted = True
            current.append("\x00")
        elif char == ";":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if depth or quoted or escaped:
        return {}
    parts.append("".join(current))
    values = {"spf": set(), "dkim": set(), "dmarc": set()}
    for part in parts[1:]:
        match = re.match(
            r"^\s*(spf|dkim|dmarc)(?:/[0-9]+)?\s*=\s*([a-z0-9_-]+)(?=\s|$)",
            part, re.IGNORECASE,
        )
        if match:
            method, value = (item.lower() for item in match.groups())
            values[method].add(value)
    return {
        method: next(iter(results)) if len(results) == 1 and next(iter(results)) in {
            "pass", "fail", "temperror"
        } else "unknown"
        for method, results in values.items()
    }


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

        result.update(_authentication_results(str(msg.get("Authentication-Results", ""))))

        dkim_sig = str(msg.get("DKIM-Signature", ""))
        domain_match = re.search(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", dkim_sig, re.IGNORECASE)
        selector_match = re.search(r"(?:^|;)\s*s\s*=\s*([^;\s]+)", dkim_sig, re.IGNORECASE)

        if domain_match:
            result["dkim_domain"] = (domain_match.group(1))

        if selector_match:
            result["dkim_selector"] = (selector_match.group(1))

    except Exception as e:
        print(f"[!] Unable to parse EML: {e}")

    return result