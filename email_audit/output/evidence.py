"""
Assessment evidence rendering.

Provides Rich table output for configuration and authentication
evidence captured during an email security assessment.
"""


from rich.table import Table
from rich.text import Text

from email_audit.constants import (
    DMARC_MAP,
    MTA_MAP,
)

from email_audit.output.console import (
    console,
    rich_assessment_colour,
)

# ---------------------------------------------------------------------------
# Authentication Evidence
# ---------------------------------------------------------------------------
def _colour_result(value):
    """
    Apply Rich colour formatting to authentication results.
    """

    value = value.upper()

    if value == "PASS":
        return Text(value, style="green")

    if value == "FAIL":
        return Text(value, style="red")

    return Text(value, style="yellow")


def report_authentication_validation(auth_results):
    """
    Display authentication validation evidence extracted from a
    supplied email sample.
    """

    table = Table(title="Authentication Evidence")

    table.add_column("Control", style="cyan")
    table.add_column("Result")

    table.add_row("SPF", _colour_result(auth_results["spf"]))
    table.add_row("DKIM", _colour_result(auth_results["dkim"]))
    table.add_row("DMARC", _colour_result(auth_results["dmarc"]))

    console.print(table)


# ---------------------------------------------------------------------------
# Configuration Evidence
# ---------------------------------------------------------------------------
def report_configuration_validation(results):
    """
    Display configuration evidence for assessed email security
    controls.
    """

    spf = results[0]
    dkim = results[1]
    dmarc = results[2]
    mta = results[3]

    table = Table(title="Configuration Evidence")

    table.add_column("Control", style="cyan")
    table.add_column("Configuration")
    table.add_column("Status")

    # SPF
    if spf.get("all_policy") == "-all":
        spf_config = "Hard Fail (-all)"
    elif spf.get("all_policy") == "~all":
        spf_config = "Soft Fail (~all)"
    elif spf.get("all_policy") in ("all", "+all"):
        spf_config = f"Permissive ({spf['all_policy']})"
    else:
        spf_config = "Not Present" if spf["assessment"] == "MISSING" else "Unknown"

    # DKIM
    selector = "Unknown"

    for item in dkim["breakdown"]:

        if item.startswith("Common selector discovered:"):
            selector = item.split(": ", 1)[1]
            break

        if item.startswith("Selector extracted from supplied email:"):
            selector = item.split(": ", 1)[1]
            break

    # DMARC
    policy = dmarc.get("tags", {}).get("p", "").lower()
    dmarc_config = DMARC_MAP.get(policy, "Not Present" if dmarc["assessment"] == "MISSING" else "Unknown")
    if dmarc.get("coverage_limited"):
        dmarc_config += " (limited)"
    elif dmarc.get("coverage_errors") and policy in {"reject", "quarantine"}:
        dmarc_config += " (coverage unknown)"

    # MTA-STS
    mode = mta.get("policy", {}).get("mode", "")
    mta_config = MTA_MAP.get(mode, "Not Present" if mta["assessment"] == "MISSING" else "Unknown")

    table.add_row("SPF", Text(spf_config), rich_assessment_colour(spf["assessment"]))
    table.add_row("DKIM", Text(selector), rich_assessment_colour(dkim["assessment"]))
    table.add_row(
        "DMARC", Text(dmarc_config), rich_assessment_colour(dmarc["assessment"])
    )

    table.add_row(
        "MTA-STS", Text(mta_config), rich_assessment_colour(mta["assessment"])
    )
    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    if tls_rpt is not None:
        table.add_row("TLS-RPT", Text(tls_rpt["assessment"]),
                      rich_assessment_colour(tls_rpt["assessment"]))

    console.print(table)