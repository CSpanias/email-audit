"""
Controlled email spoofing assessment.

Provides functionality for performing authorised email spoofing tests
and validating how email security controls respond to spoofed messages.
"""

import socket

from shutil import which

from email_audit.utils import run_command
from email_audit.output.console import (
    colour_assessment,
    print_section,
)


# ---------------------------------------------------------------------------
# SMTP Validation
# ---------------------------------------------------------------------------
def smtp_server_running():
    """
    Determine whether a local SMTP relay is available.

    Returns True if an SMTP service is reachable on localhost:25,
    otherwise returns False.
    """

    try:
        sock = socket.create_connection(("localhost", 25), timeout=3)
        sock.close()
        return True

    except Exception:
        return False


# ---------------------------------------------------------------------------
# Spoofing Assessment
# ---------------------------------------------------------------------------
def perform_spoof_test(domain, recipient):
    """
    Perform a controlled email spoofing assessment.

    Generates a spoofed message using the supplied domain and
    attempts to submit it through the local SMTP relay. The
    resulting behaviour is captured and returned for reporting
    purposes.
    """

    sender = f"ceo@{domain}"
    subject = "Subject: Controlled Spoofing Assessment"
    body = (
        "This email was generated as part of an authorised security assessment "
        f"to validate SPF, DKIM, and DMARC enforcement for the {domain} domain."
    )

    # Variables shown on the report
    result = {
        "control": "Spoofing Test",
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "assessment": "",
        "impact": ""
    }

    # Check swaks is installed
    if not which("swaks"):

        result["assessment"] = "SWAKS NOT INSTALLED"
        result["impact"] = (
            "The swaks utility is required to perform spoofing tests. Install "
            "swaks and rerun the assessment."
        )

        return result

    # Check SMTP relay
    if not smtp_server_running():

        result["assessment"] = "LOCAL SMTP RELAY NOT AVAILABLE"
        result["impact"] = (
            "No SMTP service was detected on localhost:25. Start a local SMTP "
            "relay (e.g. Postfix) before performing a spoofing assessment."
        )

        return result

    output = run_command([
        "swaks",
        "--to", recipient,
        "--from", sender,
        "--header", subject,
        "--body", body,
        "--server", "localhost"
    ])
    
    output = output.lower()

    if "queued as" in output:

        result["assessment"] = ("MESSAGE SUBMITTED")
        result["impact"] = (
            "The spoofed email was accepted by the local SMTP relay and "
            "submitted for delivery.\nRecipient-side validation is required to "
            "determine whether SPF, DKIM, and DMARC protections were "
            "successfully enforced."
        )

    elif "reject" in output:

        result["assessment"] = ("REJECTED BY SMTP RELAY")
        result["impact"] = ("The spoofed message was rejected before delivery.")

    else:

        result["assessment"] = ("UNKNOWN")
        result["impact"] = (
            "Unable to determine the result of the spoofing attempt."
        )

    return result


# ---------------------------------------------------------------------------
# Console Output
# ---------------------------------------------------------------------------
def report_spoof(result):
    """
    Display the results of a controlled spoofing assessment.
    """

    print_section("SPOOFING TEST")

    print("Test Details:")
    print(f"Sender:     {result['sender']}")
    print(f"Recipient:  {result['recipient']}")
    print(f"Subject:    {result['subject']}")

    print()

    print("Assessment:")
    print(f"{colour_assessment(result['assessment'])}")

    print()

    print("Security Impact:")
    print(f"{result['impact']}")

    print()