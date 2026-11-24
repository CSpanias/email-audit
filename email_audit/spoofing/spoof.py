"""
Controlled email spoofing assessment.

Provides functionality for performing authorised email spoofing tests
and validating how email security controls respond to spoofed messages.
"""

import os
import re
import smtplib
import subprocess
import sys

from shutil import which

from rich.table import Table
from rich.text import Text

from email_audit.utils import run_command
from email_audit.output.console import (
    colour_assessment,
    console,
    print_section,
)


# ---------------------------------------------------------------------------
# SMTP Validation
# ---------------------------------------------------------------------------
def smtp_server_running():
    """
    Determine whether a local SMTP relay accepts connections on localhost:25.
    """

    try:
        with smtplib.SMTP("localhost", 25, timeout=3):
            pass
        return True

    except (OSError, smtplib.SMTPException):
        return False


def _postfix_status(command):
    return subprocess.run(
        [*command, "status"], capture_output=True, text=True, check=False
    )


def _stop_postfix(command):
    """Stop and verify a Postfix service started by this assessment."""
    try:
        stopped = subprocess.run([*command, "stop"], check=False)
        if stopped.returncode != 0:
            raise RuntimeError(f"Postfix stop failed with exit code {stopped.returncode}")
        status = _postfix_status(command)
    except OSError as exc:
        raise RuntimeError(f"Could not stop or verify Postfix: {exc}") from exc
    if status.returncode != 3:
        detail = (status.stderr or status.stdout).strip()
        raise RuntimeError(
            f"Could not confirm Postfix stopped (status {status.returncode})"
            + (f": {detail}" if detail else "")
        )
    print("[+] Stopped the Postfix service.")


def _offer_stop_existing_relay():
    """Ask before stopping a relay that was already running."""
    service = which("service") if sys.platform.startswith("linux") else None
    if not sys.stdin.isatty() or not service:
        print("[!] The existing SMTP relay was left running; stop it manually if needed.")
        return

    command = [service, "postfix"]
    if os.geteuid() != 0:
        sudo = which("sudo")
        if not sudo:
            print("[!] sudo is unavailable; the existing SMTP relay was left running.")
            return
        command.insert(0, sudo)

    try:
        answer = input("\n[?] Stop the existing local Postfix service? [y/N]: ").strip().lower()
    except EOFError:
        print("\n[!] No answer received; the existing SMTP relay was left running.")
        return
    if answer not in {"y", "yes"}:
        print("[*] The existing SMTP relay was left running.")
        return

    try:
        status = _postfix_status(command)
    except OSError as exc:
        raise RuntimeError(f"Could not check Postfix status: {exc}") from exc
    if status.returncode == 3:
        print("[!] Postfix was not running; no service was stopped.")
    elif status.returncode == 0:
        _stop_postfix(command)
    else:
        detail = (status.stderr or status.stdout).strip()
        raise RuntimeError(
            f"Could not determine whether Postfix is running (status {status.returncode})"
            + (f": {detail}" if detail else "")
        )


def ensure_local_smtp(cleanup):
    """Offer to start Postfix when the local relay is unavailable."""
    if smtp_server_running():
        cleanup.callback(_offer_stop_existing_relay)
        return None

    unavailable = "No SMTP service was detected on localhost:25."
    if not sys.stdin.isatty():
        return f"{unavailable} Start a local SMTP relay and rerun the assessment."
    service = which("service") if sys.platform.startswith("linux") else None
    if not service:
        return f"{unavailable} Start a local SMTP relay manually and rerun the assessment."
    command = [service, "postfix"]
    if os.geteuid() != 0:
        sudo = which("sudo")
        if not sudo:
            return f"{unavailable} sudo is unavailable; start Postfix manually and rerun."
        command.insert(0, sudo)

    print(f"\n[!] {unavailable}")
    if input("[?] Start the local Postfix service now? [y/N]: ").strip().lower() not in {"y", "yes"}:
        return "Local SMTP relay was not started; the spoofing assessment was skipped."

    try:
        status = _postfix_status(command)
    except OSError as exc:
        return f"Could not check Postfix status: {exc}. The spoofing assessment was skipped."
    if status.returncode == 0:
        return "Postfix is already running but is not responding on localhost:25; the spoofing assessment was skipped."
    if status.returncode != 3:
        detail = (status.stderr or status.stdout).strip()
        return (
            f"Could not determine whether Postfix is running (status {status.returncode})"
            + (f": {detail}" if detail else "")
            + "; the spoofing assessment was skipped."
        )

    cleanup.callback(_stop_postfix, command)
    try:
        completed = subprocess.run([*command, "start"], check=False)
    except OSError as exc:
        return f"Could not start Postfix: {exc}. The spoofing assessment was skipped."
    if completed.returncode != 0:
        return f"Postfix startup failed (exit code {completed.returncode}); the spoofing assessment was skipped."
    if not smtp_server_running():
        return "Postfix started, but no SMTP service responded on localhost:25; the spoofing assessment was skipped."
    return None


# ---------------------------------------------------------------------------
# Spoofing Assessment
# ---------------------------------------------------------------------------
def perform_spoof_test(domain, recipient, cleanup):
    """
    Perform a controlled email spoofing assessment.

    Generates a spoofed message using the supplied domain and
    attempts to submit it through the local SMTP relay. The
    resulting behaviour is captured and returned for reporting
    purposes.
    """

    sender = f"ceo@{domain}"
    subject = "Controlled Spoofing Assessment"
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
    smtp_error = ensure_local_smtp(cleanup)
    if smtp_error:

        result["assessment"] = "LOCAL SMTP RELAY NOT AVAILABLE"
        result["impact"] = smtp_error

        return result

    try:
        returncode, output = run_command([
            "swaks",
            "--to", recipient,
            "--from", sender,
            "--header", f"Subject: {subject}",
            "--body", body,
            "--server", "localhost"
        ])
    except OSError as exc:
        result["assessment"] = "UNKNOWN"
        result["impact"] = f"Could not run swaks: {exc}"
        return result
    
    output = output.lower()

    if returncode == 0 and "queued as" in output:

        result["assessment"] = ("MESSAGE SUBMITTED")
        result["impact"] = (
            "The spoofed email was accepted by the local SMTP relay and "
            "submitted for delivery.\nRecipient-side validation is required to "
            "determine whether SPF, DKIM, and DMARC protections were "
            "successfully enforced."
        )

    elif re.search(r"(?m)^\s*<\*\*\s+5\d\d\b", output):

        result["assessment"] = ("REJECTED BY SMTP RELAY")
        result["impact"] = ("The local SMTP relay rejected the message before delivery; "
                            "recipient-side enforcement was not tested.")

    else:

        result["assessment"] = ("UNKNOWN")
        result["impact"] = (
            f"Unable to determine the result of the spoofing attempt (swaks exit code {returncode})."
            + (f"\nSwaks output: {output}" if output else "")
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

    table = Table()
    table.add_column("Field", style="cyan")
    table.add_column("Details", overflow="fold")
    for label, key in (("Sender", "sender"), ("Recipient", "recipient"), ("Subject", "subject")):
        table.add_row(label, Text(result[key]))
    console.print(table)
    console.print()

    print("Assessment:")
    console.print(colour_assessment(result["assessment"]))

    print()

    print("Security Impact:")
    print(f"{result['impact']}")

    print()