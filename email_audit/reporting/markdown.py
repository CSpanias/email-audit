"""
Markdown report generation.

Builds and exports assessment reports in Markdown format.
"""


from email_audit.reporting.executive_summary import (
    build_executive_summary,
)


# ---------------------------------------------------------------------------
# Markdown Export
# ---------------------------------------------------------------------------

def export_markdown(
    domain,
    commentary,
    recommendations,
    results,
    auth_results=None,
):
    """
    Export the assessment report to Markdown format.
    """

    filename = f"{domain}.md"

    executive_summary = build_executive_summary(
        domain,
        results,
        auth_results,
    )

    content = (
        f"## Executive Summary\n\n"
        f"{executive_summary}\n\n"
        f"## Technical Commentary\n\n"
        f"{commentary}\n\n"
        f"## Recommendations\n\n"
        f"{recommendations}\n"
    )

    with open(filename, "w", encoding="utf-8") as handle:
        handle.write(content)

    return filename