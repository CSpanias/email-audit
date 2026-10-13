"""
Assessment evidence rendering.

Provides Rich table output for configuration and authentication
evidence captured during an email security assessment.
"""


from rich.console import Console
from rich.table import Table

from email_audit.constants import (
    DMARC_MAP,
    MTA_MAP,
)

from email_audit.output.console import (
    rich_assessment_colour,
)


console = Console()


# ---------------------------------------------------------------------------
# Authentication Evidence
# ---------------------------------------------------------------------------
def _colour_result(value):
    """
    Apply Rich colour formatting to authentication results.
    """

    value = value.upper()

    if value == "PASS":
        return f"[green]{value}[/green]"

    if value == "FAIL":
        return f"[red]{value}[/red]"

    return f"[yellow]{value}[/yellow]"


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
    if "-all" in spf["raw"]:
        spf_config = "Hard Fail (-all)"
    elif "~all" in spf["raw"]:
        spf_config = "Soft Fail (~all)"
    elif "+all" in spf["raw"]:
        spf_config = "Permissive (+all)"
    else:
        spf_config = "Not Present"

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
    policy = dmarc.get("tags", {}).get("p", "")
    dmarc_config = DMARC_MAP.get(policy, "Not Present")

    # MTA-STS
    mode = mta.get("policy", {}).get("mode", "")
    mta_config = MTA_MAP.get(mode, "Not Present")

    table.add_row("SPF", spf_config, rich_assessment_colour(spf["assessment"]))
    table.add_row("DKIM", selector, rich_assessment_colour(dkim["assessment"]))
    table.add_row(
        "DMARC", dmarc_config,rich_assessment_colour(dmarc["assessment"])
    )

    table.add_row(
        "MTA-STS", mta_config, rich_assessment_colour(mta["assessment"])
    )

    console.print(table)