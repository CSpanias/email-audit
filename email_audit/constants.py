"""
Project-wide constants and static reference data.

This module contains control descriptions, findings mappings, reporting
references, display mappings, terminal colour definitions and other
static values used throughout Email-Audit.
"""


# ---------------------------------------------------------------------------
# Terminal Output Colours
# ---------------------------------------------------------------------------
COLOR_GREEN = "\033[0;32m"
COLOR_RED = "\033[0;31m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[0;36m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

# ---------------------------------------------------------------------------
# Control Definitions
#
# Used throughout generated reports to provide concise explanations of
# the assessed email security controls.
# ---------------------------------------------------------------------------
CONTROL_DEFINITIONS = {

    "SPF":
        "Sender Policy Framework (SPF) is an email authentication mechanism "
        "that enables domain owners to explicitly identify the systems "
        "authorised to send email on behalf of the domain.",

    "DKIM":
        "DomainKeys Identified Mail (DKIM) is an email authentication "
        "mechanism that uses cryptographic signatures to allow receiving "
        "mail systems to verify that messages were authorised by the sending "
        "domain and were not modified in transit.",

    "DMARC":
        "Domain-based Message Authentication, Reporting and Conformance "
        "(DMARC) is an email authentication and policy framework that builds "
        "upon SPF and DKIM by instructing receiving organisations how to "
        "handle messages that fail authentication checks.",

    "MTA-STS":
        "Mail Transfer Agent Strict Transport Security (MTA-STS) is an "
        "email transport security mechanism that helps ensure SMTP "
        "communications are delivered over trusted TLS-encrypted channels "
        "and reduces the risk of downgrade attacks."
}

# ---------------------------------------------------------------------------
# Reference Material
#
# Industry guidance, standards and vendor-independent references used
# within generated remediation sections.
# ---------------------------------------------------------------------------
REFERENCES = {
    "cccs": "https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection",
    "ncsc": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing",
    "spf": "https://datatracker.ietf.org/doc/html/rfc7208",
    "dkim": "https://datatracker.ietf.org/doc/html/rfc6376",
    "dmarc": "https://datatracker.ietf.org/doc/html/rfc7489",
    "dmarc_org": "https://dmarc.org/resources/",
    "mta_sts": "https://datatracker.ietf.org/doc/html/rfc8461"
}

# ---------------------------------------------------------------------------
# Findings Mapping
#
# Maps assessment outcomes to generic findings that can be exported to
# JSON and consumed by downstream reporting platforms.
# ---------------------------------------------------------------------------
FINDING_MAP = {

    ("SPF", "MISSING"): {
        "id": "missing-spf",
        "description": "No SPF record was identified for {domain}."
    },

    ("SPF", "INSECURE"): {
            "id": "permissive-spf",
            "description": (
                "The SPF record for {domain} contains '+all', permitting any "
                "host on the Internet to send email on behalf of the domain."
            )
        },

    ("DMARC", "MISSING"): {
        "id": "missing-dmarc",
        "description": "No DMARC record was identified for {domain}."
    },

    ("DKIM", "UNKNOWN"): {
        "id": "missing-dkim",
        "description": "No DKIM selector could be identified for {domain}."
    },

    ("MTA-STS", "MISSING"): {
        "id": "missing-mta-sts",
        "description": "No MTA-STS policy was identified for {domain}."
    },

    ("MTA-STS", "UNKNOWN"): {
        "id": "invalid-mta-sts",
        "description": (
            "An MTA-STS DNS record was identified for {domain}; however, the "
            "associated policy could not be retrieved or validated."
        )
    },
}

# ---------------------------------------------------------------------------
# Report Display Mappings
#
# Converts raw policy values into human-readable reporting terminology.
# ---------------------------------------------------------------------------
MTA_MAP = {
        "enforce": "Enforce",
        "testing": "Testing",
        "none": "Disabled"
    }

DMARC_MAP = {
    "reject": "Reject",
    "quarantine": "Quarantine",
    "none": "Monitoring"
}

# ---------------------------------------------------------------------------
# Domain-based Message Authentication, Reporting and Conformance (DMARC) 
# reporting values.
# ---------------------------------------------------------------------------
COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google"]