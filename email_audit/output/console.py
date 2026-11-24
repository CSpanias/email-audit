"""Consistent Rich console output for email assessments."""

from rich.console import Console
from rich.text import Text

console = Console()


def colour_assessment(value):
    if value in {"SECURE", "PRESENT", "MESSAGE SUBMITTED"}:
        style = "green"
    elif value in {"ACCEPTABLE", "UNKNOWN", "NOT APPLICABLE"}:
        style = "yellow"
    else:
        style = "red"
    return Text(value, style=style)


def rich_assessment_colour(status):
    return colour_assessment(status)


def print_info(message):
    console.print(Text.assemble(("[*]", "cyan"), f" {message}"))
    console.print()


def print_section(title):
    console.print(Text(f"=== {title} ===", style="bold cyan"))
    console.print()


def print_domain_header(domain):
    console.print(Text(f"\n{domain.upper()}\n", style="bold cyan"))


def print_assessment(result):
    print_section(result["control"])

    if result["raw"]:
        console.print("Raw Record:", style="bold")
        console.print(result["raw"], markup=False)
        console.print()

    console.print("Breakdown:", style="bold")
    for item in result["breakdown"]:
        console.print(f"  - {item}", markup=False)
    console.print()

    console.print("Security Impact:", style="bold")
    console.print(f"  {result['impact']}", markup=False)
    console.print()

    console.print("Assessment:", style="bold")
    console.print(Text("  ") + colour_assessment(result["assessment"]))
    console.print()


def print_completion_summary(
    findings,
    findings_file,
    html_file,
    output_format="JSON",
    exported_count=None,
):
    console.print()
    console.print(Text.assemble(("[+]", "green"), " Assessment Complete"))
    console.print()
    count = len(findings) if exported_count is None else exported_count
    console.print(f"    Findings Exported : {count}", markup=False)
    console.print(f"    {output_format} Output       : {findings_file}", markup=False)
    console.print(f"    HTML Output       : {html_file}", markup=False)
    console.print()
