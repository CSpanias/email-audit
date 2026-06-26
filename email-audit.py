#!/usr/bin/env python3

"""
Email Security Audit Tool (PoC)

Author: Charalampos Spanias

Description:
This tool performs a basic email security assessment for a given domain.
It evaluates the following:

- SPF configuration (DNS)
- DMARC configuration (DNS)
- DKIM presence (DNS-based detection)
- MTA-STS presence (DNS)
- Optional spoofing test (via local MTA using swaks)
- Optional email-based validation using a .eml file

The goal is to provide an educational breakdown of how email
security controls are configured and how they behave in practice.
"""

import argparse
import subprocess
import re

# ------------------------------------------------------------
# CLI formatting (basic colour support)
# ------------------------------------------------------------
COLOR_GREEN = "\033[0;32m"
COLOR_RED = "\033[0;31m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[0;36m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


# ------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------
def run_command(command):
    """
    Execute a system command and return output.
    Returns empty string on failure.
    """
    try:
        return subprocess.check_output(
            command,
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return ""


def print_section(title):
    """
    Print a formatted section header.
    """
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}=== {title} ==={COLOR_RESET}\n")


def print_domain_header(domain):
    """
    Display the domain in a consistent format.
    """
    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{domain.upper()}{COLOR_RESET}")


# ------------------------------------------------------------
# DNS Collection
# ------------------------------------------------------------
def get_spf_record(domain):
    """
    Retrieve SPF record from DNS.
    """
    output = run_command(["dig", "+short", domain, "TXT"])

    for line in output.splitlines():
        if "v=spf1" in line:
            return line.strip('"')

    return ""


def get_dmarc_record(domain):
    """
    Retrieve DMARC record from DNS.
    """
    output = run_command(["dig", "+short", f"_dmarc.{domain}", "TXT"])

    for line in output.splitlines():
        if "v=DMARC1" in line:
            return line.strip('"')

    return ""


def parse_dmarc_record(record):
    """
    Extract important DMARC tags.
    """
    parsed = {
        "policy": "missing",
        "pct": "",
        "rua": "",
        "adkim": "",
        "aspf": ""
    }

    if not record:
        return parsed

    # Determine policy
    if "p=reject" in record:
        parsed["policy"] = "reject"
    elif "p=quarantine" in record:
        parsed["policy"] = "quarantine"
    elif "p=none" in record:
        parsed["policy"] = "none"

    # Extract tags
    for tag in ["pct", "rua", "adkim", "aspf"]:
        match = re.search(rf"{tag}=([^;]+)", record)
        if match:
            parsed[tag] = match.group(1)

    return parsed


def check_mta_sts(domain):
    """
    Check if MTA-STS DNS record exists.
    """
    output = run_command(["dig", "+short", f"_mta-sts.{domain}", "TXT"])
    return bool(output)


def check_dkim_dns(domain):
    """
    Attempt to identify DKIM using common selectors.
    """
    common_selectors = ["default", "selector1", "selector2", "google"]

    for selector in common_selectors:
        output = run_command([
            "dig",
            "+short",
            f"{selector}._domainkey.{domain}",
            "TXT"
        ])

        if output:
            return True, selector

    return False, ""


# ------------------------------------------------------------
# Spoof test
# ------------------------------------------------------------
def perform_spoof_test(domain, target_email):
    """
    Attempt to send a spoofed email using local MTA.
    """
    print_section("Spoofing Test")

    print(f"[*] Sending spoofed message as ceo@{domain} → {target_email}")

    output = run_command([
        "swaks",
        "--to", target_email,
        "--from", f"ceo@{domain}",
        "--server", "localhost"
    ])

    if "queued as" in output.lower():
        print(f"{COLOR_GREEN}Message accepted by local MTA{COLOR_RESET}")
    elif "reject" in output.lower():
        print(f"{COLOR_RED}Message rejected{COLOR_RESET}")
    else:
        print(f"{COLOR_YELLOW}Unable to determine result{COLOR_RESET}")


# ------------------------------------------------------------
# EML parsing
# ------------------------------------------------------------
def parse_eml_file(path):
    """
    Extract authentication results from EML file.
    Supports both standard and Microsoft-style headers.
    """
    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "dkim_domain": "",
        "dkim_selector": ""
    }

    try:
        with open(path, "r", errors="ignore") as f:
            raw = f.read().lower()

        # SPF (Microsoft-style header)
        if "received-spf: pass" in raw:
            result["spf"] = "pass"
        elif "received-spf: fail" in raw:
            result["spf"] = "fail"

        # Generic authentication-results parsing
        if "spf=pass" in raw:
            result["spf"] = "pass"
        elif "spf=fail" in raw:
            result["spf"] = "fail"

        if "dkim=pass" in raw:
            result["dkim"] = "pass"
        elif "dkim=fail" in raw:
            result["dkim"] = "fail"

        if "dmarc=pass" in raw:
            result["dmarc"] = "pass"
        elif "dmarc=fail" in raw:
            result["dmarc"] = "fail"

        # Extract DKIM signature details
        match = re.search(
            r"dkim-signature:.*?d=([^\s;]+).*?s=([^\s;]+)",
            raw,
            re.DOTALL
        )

        if match:
            result["dkim_domain"] = match.group(1)
            result["dkim_selector"] = match.group(2)

    except Exception:
        pass

    return result


# ------------------------------------------------------------
# Reporting functions
# ------------------------------------------------------------
def report_spf(spf, domain):
    print_section("SPF")

    if not spf:
        print(f"[!] No SPF record found for '{domain}'\n")
        return

    print(f"Raw record: \"{spf}\"\n")

    print(f"[*] An SPF record is present for '{domain}'")

    elements = spf.split()

    # Extract authorised senders
    authorised = []

    for e in elements:
        if e.startswith("ip4:"):
            authorised.append(e.replace("ip4:", ""))
        elif e.startswith("ip6:"):
            authorised.append(e.replace("ip6:", ""))
        elif e.startswith("include:"):
            authorised.append(e.replace("include:", "") + " (via include)")

    if authorised:
        print(f"\n[+] The following sending sources are authorised:")
        for entry in authorised:
            print(f"    - {entry}")

    # Enforcement
    if "-all" in elements:
        print(f"\n[+] SPF is enforced with a hard fail (-all), meaning unauthorised senders should be rejected")
    elif "~all" in elements:
        print(f"\n[~] SPF uses a softfail (~all), meaning unauthorised senders may still be accepted")
    else:
        print(f"\n[~] SPF does not clearly define enforcement behaviour")

    print()

def report_dmarc(record, parsed, domain):
    print_section("DMARC")

    if not record:
        print(f"[!] No DMARC record found for '{domain}'\n")
        return

    print(f"Raw record: \"{record}\"\n")

    print(f"[*] A DMARC record is present for '{domain}'")

    # Policy
    if parsed["policy"] == "reject":
        print(f"[+] p=reject: Emails that fail SPF or DKIM should be rejected")
    elif parsed["policy"] == "quarantine":
        print(f"[~] p=quarantine: Failed emails may be sent to spam")
    elif parsed["policy"] == "none":
        print(f"[!] p=none: DMARC is not enforced (monitoring only)")

    # pct
    if parsed["pct"]:
        print(f"[*] pct={parsed['pct']}: {parsed['pct']}% of email is subject to DMARC evaluation")

    # rua
    if parsed["rua"]:
        print(f"[+] rua: Aggregate reports are sent to:")
        for r in parsed["rua"].split(","):
            print(f"    - {r.replace('mailto:', '')}")

    # alignment
    if parsed["adkim"]:
        mode = "Relaxed" if parsed["adkim"] == "r" else "Strict"
        print(f"[~] adkim={parsed['adkim']} ({mode}): DKIM alignment mode")

    if parsed["aspf"]:
        mode = "Relaxed" if parsed["aspf"] == "r" else "Strict"
        print(f"[~] aspf={parsed['aspf']} ({mode}): SPF alignment mode")

    print()

def report_dkim(present, selector):
    print_section("DKIM")

    if present:
        print(f"DKIM record detected using selector: {selector}\n")
        print(f"- selector={selector} -> DNS record used to retrieve the public key")
        print("- DKIM -> enables cryptographic signing of emails for integrity and authenticity\n")
    else:
        print("No common DKIM selectors detected\n")
        print("- DKIM -> could not be confirmed via DNS (may still exist with non-standard selectors)\n")


def report_mta_sts(enabled):
    print_section("MTA-STS")

    if enabled:
        print("MTA-STS record detected\n")
        print("- MTA-STS -> enforces TLS for email transmission between mail servers\n")
    else:
        print("No MTA-STS record found\n")
        print("- MTA-STS -> not in use, allowing potential downgrade attacks\n")


def report_eml(results):
    print_section("Observed Authentication Results")

    print("[*] Authentication results from analysed email:\n")

    # SPF
    if results["spf"] == "pass":
        print("[+] SPF result: pass")
    elif results["spf"] == "fail":
        print("[!] SPF result: fail")
        print("    - Sending server is not authorised by SPF")
    else:
        print("[~] SPF result: not observed")

    # DKIM
    if results["dkim"] == "pass":
        print("[+] DKIM result: pass")
    elif results["dkim"] == "fail":
        print("[!] DKIM result: fail")
    else:
        print("[~] DKIM result: not observed")

    # DMARC
    if results["dmarc"] == "pass":
        print("[+] DMARC result: pass")
    elif results["dmarc"] == "fail":
        print("[!] DMARC result: fail")
    else:
        print("[~] DMARC result: not observed")
        print("    - Receiving system may not explicitly expose DMARC outcome")

    print()

# ------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Email security assessment tool"
    )

    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--spoof", action="store_true", help="Run spoof test")
    parser.add_argument("--to", help="Target email for spoof test")
    parser.add_argument("--eml", help="Path to EML file")

    args = parser.parse_args()

    print_domain_header(args.domain)

    # Collect DNS data
    spf = get_spf_record(args.domain)
    dmarc_raw = get_dmarc_record(args.domain)
    dmarc = parse_dmarc_record(dmarc_raw)
    mta = check_mta_sts(args.domain)
    dkim_present, selector = check_dkim_dns(args.domain)

    # Report
    report_spf(spf, args.domain)
    report_dmarc(dmarc_raw, dmarc, args.domain)
    report_dkim(dkim_present, selector)
    report_mta_sts(mta)

    # Optional features
    if args.spoof:
        if args.to:
            perform_spoof_test(args.domain, args.to)
        else:
            print("Error: --spoof requires --to <email>")

    if args.eml:
        eml_results = parse_eml_file(args.eml)
        report_eml(eml_results)


if __name__ == "__main__":
    main()