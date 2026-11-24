"""DNS TXT lookups with explicit errors for inconclusive responses."""

import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """A DNS response could not be obtained or decoded."""


def get_txt_records(name):
    """Return decoded TXT records, or raise when the lookup is inconclusive."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=10, search=False)
        return ["".join(part.decode("utf-8") for part in answer.strings) for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, UnicodeDecodeError) as exc:
        raise DNSLookupError(f"{name}: {str(exc) or type(exc).__name__}") from exc
