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