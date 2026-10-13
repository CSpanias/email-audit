"""
Console output helpers.

Provides terminal rendering functions for displaying assessment
results, security posture and section headings.
"""

from rich.console import Console

from email_audit.constants import (
    COLOR_BOLD,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_RESET,
    COLOR_YELLOW,
)


def colour_assessment(value):

    green = {"SECURE", "PRESENT", "MESSAGE SUBMITTED"}
    yellow = {"ACCEPTABLE"}
    red = {"INSECURE", "MISSING", "UNKNOWN", "REJECTED BY SMTP RELAY", "LOCAL SMTP RELAY NOT AVAILABLE"}

    if value in green:
        return f"{COLOR_GREEN}{value}{COLOR_RESET}"

    elif value in yellow:
        return f"{COLOR_YELLOW}{value}{COLOR_RESET}"

    elif value in red:
        return f"{COLOR_RED}{value}{COLOR_RESET}"

    return value

def colour_posture(value):

    if value in ["EXCELLENT", "GOOD"]:
        return f"{COLOR_GREEN}{value}{COLOR_RESET}"

    elif value == "MODERATE":
        return f"{COLOR_YELLOW}{value}{COLOR_RESET}"

    return f"{COLOR_RED}{value}{COLOR_RESET}"

def colour_auth_result(value):

    value_upper = value.upper()

    if value_upper == "PASS":
        return (f"{COLOR_GREEN}{value_upper}{COLOR_RESET}")

    elif value_upper == "FAIL":
        return (f"{COLOR_RED}{value_upper}{COLOR_RESET}")

    return (f"{COLOR_YELLOW}{value_upper}{COLOR_RESET}")


def rich_assessment_colour(status):

    if status in ["SECURE", "PRESENT"]:
        return f"[green]{status}[/green]"

    elif status == "ACCEPTABLE":
        return f"[yellow]{status}[/yellow]"

    return f"[red]{status}[/red]"


def print_section(title):
    """
    Display a formatted section heading.
    """

    print(f"{COLOR_CYAN}{COLOR_BOLD}=== {title} ==={COLOR_RESET}\n")


def print_domain_header(domain):
    """
    Display the target domain banner.
    """

    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{domain.upper()}{COLOR_RESET}\n")


def print_assessment(result):
    """
    Display the detailed assessment result for a control.
    """

    print_section(result["control"])
    
    if result["raw"]:
        print("Raw Record:")
        print(result["raw"])
        print()

    print("Breakdown:")

    for item in result["breakdown"]:
        print(f"  - {item}")

    print()

    print("Security Impact:")
    print(f"  {result['impact']}")
    print()

    print("Assessment:")
    print(f"  {colour_assessment(result['assessment'])}")
    print()



def print_posture(results):
    """
    Display the overall email security posture and score.
    """

    total_score = sum(r["score"] for r in results)
    max_score = sum(r["max_score"] for r in results)

    percentage = total_score / max_score

    if percentage == 1:
        overall = "EXCELLENT"
    elif percentage >= 0.75:
        overall = "GOOD"
    elif percentage >= 0.50:
        overall = "MODERATE"
    else:
        overall = "WEAK"

    print()
    print("Overall Security Posture: "
          f"{colour_posture(overall)} ({total_score}/{max_score})")
    print()


def print_completion_summary(
    findings,
    json_file,
    md_file,
):
    """
    Display the assessment completion summary.
    """

    print()

    print(f"{COLOR_GREEN}[+] Assessment Complete{COLOR_RESET}")

    print()

    print(f"    Findings Exported : {len(findings)}")
    print(f"    JSON Output       : {json_file}")
    print(f"    Markdown Output   : {md_file}")

    print()