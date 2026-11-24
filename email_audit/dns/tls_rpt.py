"""Discover and assess SMTP TLS reporting policies."""

import re
from urllib.parse import urlsplit

import dns.exception
import dns.resolver


def get_tls_rpt_records(domain):
    """Return decoded TXT records, or an explanatory error for inconclusive DNS."""
    try:
        answers = dns.resolver.resolve(f"_smtp._tls.{domain}", "TXT", lifetime=10, search=False)
        return ["".join(part.decode("utf-8") for part in answer.strings) for answer in answers], None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except (dns.exception.DNSException, UnicodeDecodeError) as exc:
        return [], str(exc) or type(exc).__name__


def _valid_uri(value):
    if not value or re.search(r"[\s!;]|%(?![0-9a-fA-F]{2})", value):
        return False
    try:
        parsed = urlsplit(value)
        if parsed.scheme == "https":
            return bool(parsed.hostname) and parsed.port != 0
        if parsed.scheme == "mailto":
            return not parsed.netloc and bool(re.fullmatch(r"[^@\s]+@[^@\s]+", parsed.path))
    except ValueError:
        return False
    return False


def assess_tls_rpt(records, error=None):
    """Assess one TLS-RPT policy without treating DNS failures as absence."""
    result = {
        "control": "TLS-RPT",
        "raw": "\n".join(records),
        "breakdown": [],
        "assessment": "UNKNOWN",
        "impact": "",
    }
    if error is not None:
        result["breakdown"].append(f"DNS lookup failed: {error}")
        result["impact"] = "TLS reporting configuration could not be determined."
        return result

    candidates = [record for record in records if record.startswith("v=TLSRPTv1")]
    if not candidates:
        result["assessment"] = "MISSING"
        result["breakdown"].append("No TLS-RPT policy record found")
        result["impact"] = "SMTP TLS delivery failures may not be reported to the domain owner."
        return result

    reason = ""
    if len(candidates) != 1:
        reason = "Multiple TLS-RPT policy records were found"
    else:
        fields = candidates[0].split(";")
        if fields[0].rstrip(" \t") != "v=TLSRPTv1" or len(fields) < 2:
            reason = "The TLS-RPT version or field delimiter is invalid"
        else:
            tags = {}
            for index, field in enumerate(fields[1:], start=1):
                field = field.strip()
                if not field and index == len(fields) - 1:
                    continue
                if "=" not in field:
                    reason = "The TLS-RPT record contains a malformed field"
                    break
                key, value = field.split("=", 1)
                if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", key)
                        or not value or key in tags):
                    reason = "The TLS-RPT record contains an invalid or duplicate field"
                    break
                if key != "rua" and not re.fullmatch(r"[\x21-\x3a\x3c\x3e-\x7e]+", value):
                    reason = "The TLS-RPT record contains an invalid extension"
                    break
                tags[key] = value
            if not reason:
                uris = [uri.strip() for uri in tags.get("rua", "").split(",")]
                if not all(_valid_uri(uri) for uri in uris):
                    reason = "The TLS-RPT record has a missing or invalid reporting URI"
                else:
                    result["assessment"] = "PRESENT"
                    result["breakdown"].extend(f"Reporting destination: {uri}" for uri in uris)
                    result["impact"] = "Compatible sending servers can report SMTP TLS delivery issues."
                    return result

    result["assessment"] = "INVALID"
    result["breakdown"].append(reason)
    result["impact"] = "The TLS-RPT policy may not be usable for delivery reports."
    return result
