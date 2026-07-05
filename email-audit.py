#!/usr/bin/env python3

"""
Email-Audit

Author: Charalampos Spanias (mollysec)

A lightweight email security assessment tool for analysing
SPF, DKIM, DMARC, and MTA-STS configurations, validating
authentication results from exported emails, and performing
controlled spoofing assessments.

Article:
Email Security Explained: SPF, DKIM, DMARC, and MTA-STS
https://mollysec.com/posts/email-security-explained/
"""

import argparse
import subprocess
import re
import socket
import urllib.request
from email import policy
from email.parser import BytesParser

# ------------------------------------------------------------
# Formatting
# ------------------------------------------------------------

COLOR_GREEN = "\033[0;32m"
COLOR_RED = "\033[0;31m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[0;36m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


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

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def run_command(command):
    
    try:
        return subprocess.check_output(command, stderr=subprocess.STDOUT).decode().strip()
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {e.output.decode()}")
        return ""


def print_section(title):
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}=== {title} ==={COLOR_RESET}\n")


def print_domain_header(domain):
    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{domain.upper()}{COLOR_RESET}")


def print_assessment(result):
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


# ------------------------------------------------------------
# DNS Retrieval
# ------------------------------------------------------------

def get_spf_record(domain):
    output = run_command(["dig", "+short", domain, "TXT"])

    for line in output.splitlines():
        if "v=spf1" in line:
            return line.strip('"')

    return ""


def get_dmarc_record(domain):
    output = run_command(["dig", "+short", f"_dmarc.{domain}", "TXT"])

    for line in output.splitlines():
        if "v=DMARC1" in line:
            return line.strip('"')

    return ""


def check_mta_sts(domain):
    output = run_command(
        ["dig", "+short", f"_mta-sts.{domain}", "TXT"]
    )
    return output.strip()


def check_dkim_dns(domain, selector=None):

    # Common selectors
    selectors = ([selector] if selector else COMMON_DKIM_SELECTORS)

    for selector in selectors:

        output = run_command([
            "dig",
            "+short",
            f"{selector}._domainkey.{domain}",
            "TXT"
        ])

        if not output:
            continue

        # Valid DKIM record
        if "v=DKIM1" in output:
            return selector, output, True

        # If output returned, but not DKIM record -> possible CNAME target
        target = output.strip().rstrip(".")
        dkim_record = run_command(["dig", "+short", target, "TXT"])

        if "v=DKIM1" in dkim_record:
            return selector, dkim_record, True

        return selector, output, False

    return "", "", False


# ------------------------------------------------------------
# SPF Assessment
# ------------------------------------------------------------

def assess_spf(record):

    result = {
        "control": "SPF",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "",
        "score": 0,
        "max_score": 3
    }

    if not record:
        result["breakdown"].append("No SPF record present")
        result["impact"] = ("Receiving systems cannot determine which mail servers are authorised to send email.")
        result["assessment"] = "MISSING"

        return result

    elements = record.split()

    for element in elements:

        if element.startswith("include:"):
            result["breakdown"].append(f"{element} → Authorised third-party provider")

        elif element.startswith("ip4:"):
            result["breakdown"].append(f"{element} → Authorised IPv4 sender")

        elif element.startswith("ip6:"):
            result["breakdown"].append(f"{element} → Authorised IPv6 sender")

        elif element.endswith("all"):
            result["breakdown"].append(f"{element} → SPF enforcement policy")

    if "-all" in elements:

        result["impact"] = ("Unauthorised sending mail servers should be rejected.")
        result["assessment"] = "SECURE"
        result["score"] = 3

    elif "~all" in elements:

        result["impact"] = ("Unauthorised senders may still be accepted by some recipients.")
        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2

    elif "+all" in elements:

        result["impact"] = ("Any sender is effectively authorised to send email.")
        result["assessment"] = "INSECURE"
        result["score"] = 0

    else:

        result["impact"] = ("SPF enforcement behaviour could not be clearly determined.")
        result["assessment"] = "UNKNOWN"
        result["score"] = 0

    return result


# ------------------------------------------------------------
# DMARC Assessment
# ------------------------------------------------------------

def assess_dmarc(record):

    result = {
        "control": "DMARC",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "",
        "score": 0,
        "max_score": 3
    }

    if not record:

        result["breakdown"].append("No DMARC record present")
        result["impact"] = ("Receiving servers are not given any policy for handling authentication failures.")
        result["assessment"] = "MISSING"
        result["score"] = 0

        return result

    tags = {}

    for part in record.split(";"):

        part = part.strip()

        if "=" in part:
            k, v = part.split("=", 1)
            tags[k] = v

    if "p" in tags:
        policy_text = {
            "reject": "Failed messages should be rejected",
            "quarantine": "Failed messages should be treated as suspicious",
            "none": "Monitoring only; no enforcement"
        }

        result["breakdown"].append(f"p={tags['p']} → {policy_text.get(tags['p'], '')}")

    if "pct" in tags:
        result["breakdown"].append(f"pct={tags['pct']} → Policy applies to {tags['pct']}% of messages")

    if "rua" in tags:
        result["breakdown"].append(f"rua={tags['rua']} → Aggregate DMARC reports destination")

    if "fo" in tags:
        result["breakdown"].append(f"fo={tags['fo']} → Defines when failure reports are generated")

    if "sp" in tags:
        result["breakdown"].append(f"sp={tags['sp']} → Policy applied to subdomains")

    if "adkim" in tags:
        mode = "Strict" if tags["adkim"] == "s" else "Relaxed"
        result["breakdown"].append(f"adkim={tags['adkim']} → {mode} DKIM alignment")

    if "aspf" in tags:
        mode = "Strict" if tags["aspf"] == "s" else "Relaxed"
        result["breakdown"].append(f"aspf={tags['aspf']} → {mode} SPF alignment")


    policy = tags.get("p", "")

    if policy == "reject":

        result["impact"] = ("Messages failing SPF or DKIM should be rejected.")
        result["assessment"] = "SECURE"
        result["score"] = 3

    elif policy == "quarantine":

        result["impact"] = ("Messages failing authentication should normally be treated as suspicious.")
        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2

    elif policy == "none":

        result["impact"] = ("Authentication failures are monitored but not enforced.")
        result["assessment"] = "INSECURE"
        result["score"] = 0

    else:

        result["impact"] = ("Policy could not be clearly determined.")
        result["assessment"] = "UNKNOWN"
        result["score"] = 0

    return result


# ------------------------------------------------------------
# DKIM Assessment
# ------------------------------------------------------------

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google"]

def assess_dkim(selector, record, dkim_found):

    result = {
        "control": "DKIM",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "",
        "score": 0,
        "max_score": 1
    }

    if not record:

        result["breakdown"].append("No common selector detected")
        result["impact"] = ("DKIM support could not be confirmed through DNS.")
        result["assessment"] = "UNKNOWN"

        return result
    
    if selector in COMMON_DKIM_SELECTORS:
        result["breakdown"].append(f"Common selector discovered: {selector}")
    else:
        result["breakdown"].append(f"Selector extracted from supplied email: {selector}")
        
    if dkim_found:

        result["breakdown"].append("Public key present in DNS")
        result["impact"] = ("The domain supports DKIM signature validation. Actual implementation still requires inspection of a received email.")
        result["assessment"] = "PRESENT"
        result["score"] = 1

    else:

        result["breakdown"].append("Selector delegation identified")
        result["breakdown"].append("No DKIM public key could be confirmed")
        result["impact"] = ("A DKIM selector was identified, however a corresponding DKIM public key could not be verified automatically.")
        result["assessment"] = "UNKNOWN"

    return result


# ------------------------------------------------------------
# MTA-STS Assessment
# ------------------------------------------------------------

def assess_mta_sts(record, policy):

    result = {
        "control": "MTA-STS",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": "UNKNOWN",
        "score": 0,
        "max_score": 3
    }

    if not record:

        result["breakdown"].append(
            "No MTA-STS record present"
        )

        result["impact"] = (
            "SMTP delivery may rely solely on "
            "opportunistic TLS."
        )

        result["assessment"] = "MISSING"

        return result

    # DNS record exists

    result["breakdown"].append(
        "Domain advertises support for MTA-STS"
    )

    if policy["version"]:
        result["breakdown"].append(
            f"version={policy['version']} → Policy version"
        )

    if policy["mode"]:
        result["breakdown"].append(
            f"mode={policy['mode']} → Enforcement mode"
        )

    for mx in policy["mx"]:
        result["breakdown"].append(
            f"mx={mx} → Authorised mail server"
        )

    if policy["max_age"]:
        result["breakdown"].append(
            f"max_age={policy['max_age']} → Policy cache duration"
        )

    mode = policy.get("mode", "")

    if mode == "enforce":

        result["impact"] = (
            "Compatible mail servers should only "
            "deliver email over validated TLS "
            "connections."
        )

        result["assessment"] = "SECURE"
        result["score"] = 3

    elif mode == "testing":

        result["impact"] = (
            "TLS failures can be monitored, but "
            "the policy is not yet fully enforced."
        )

        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2

    elif mode == "none":

        result["impact"] = (
            "MTA-STS is published but not enforced."
        )

        result["assessment"] = "INSECURE"
        result["score"] = 0

    else:

        result["impact"] = (
            "MTA-STS support is advertised, but "
            "the policy could not be retrieved or "
            "parsed successfully."
        )

        result["assessment"] = "PRESENT"
        result["score"] = 1

    return result
    

# MTA-STS Retrieval
def get_mta_sts_policy(domain):

    url = (f"https://mta-sts.{domain}/.well-known/mta-sts.txt")

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return (
                response.read()
                .decode()
                .strip()
            )
    except Exception:
        return ""

# MTA-STS Parsing
def parse_mta_sts_policy(policy):

    result = {
        "version": "",
        "mode": "",
        "mx": [],
        "max_age": ""
    }

    if not policy:
        return result

    for line in policy.splitlines():

        line = line.strip()

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        key = key.strip().lower()
        value = value.strip()

        if key == "version":
            result["version"] = value

        elif key == "mode":
            result["mode"] = value

        elif key == "mx":
            result["mx"].append(value)

        elif key == "max_age":
            result["max_age"] = value

    return result


# ------------------------------------------------------------
# Spoofing Implementation
# ------------------------------------------------------------

# Check if local SMTP is up
def smtp_server_running():

    try:
        sock = socket.create_connection(("localhost", 25), timeout=3)
        sock.close()
        return True

    except Exception:
        return False

# Perform the spoofing test
def perform_spoof_test(domain, recipient):

    subject = "Subject: Controlled Spoofing Assessment"
    body = f"This email was generated as part of an authorised security assessment to validate SPF, DKIM, and DMARC enforcement for the {domain} domain."
    sender = f"ceo@{domain}"

    # Variables shown on the report
    result = {
        "control": "Spoofing Test",
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "assessment": "",
        "impact": ""
    }
    
    # Check if an SMPT server is available
    if not smtp_server_running():

        result["assessment"] = ("LOCAL SMTP RELAY NOT AVAILABLE")
        result["impact"] = ("No SMTP service was detected on localhost:25. Start a local SMTP relay (e.g. Postfix) before performing a spoofing assessment.")

        return result

    output = run_command([
        "swaks",
        "--to", recipient,
        "--from", sender,
        "--header", subject,
        "--body", body,
        "--server", "localhost"
    ])

    # Code for debugging SWAKS errors
    #print(repr(output))
    
    output = output.lower()

    if "queued as" in output:

        result["assessment"] = ("MESSAGE SUBMITTED")
        result["impact"] = ("The spoofed email was accepted by the local SMTP relay and submitted for delivery. "
            "Recipient-side validation is required to determine whether SPF, DKIM, and DMARC protections were successfully enforced.")

    elif "reject" in output:

        result["assessment"] = ("REJECTED BY SMTP RELAY")
        result["impact"] = ("The spoofed message was rejected before delivery.")

    else:

        result["assessment"] = ("UNKNOWN")
        result["impact"] = ("Unable to determine the result of the spoofing attempt.")

    return result


def report_spoof(result):

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
    print(f"  {result['impact']}")

    print()


# ------------------------------------------------------------
# EML Implementation
# ------------------------------------------------------------

# EML Parsing
def parse_eml_file(path):

    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "dkim_domain": "",
        "dkim_selector": ""
    }

    try:

        with open(path, "rb") as f:
            msg = BytesParser(
                policy=policy.default
            ).parse(f)

        auth_results = str(
            msg.get("Authentication-Results", "")
        ).lower()

        if "spf=pass" in auth_results:
            result["spf"] = "pass"
        elif "spf=fail" in auth_results:
            result["spf"] = "fail"

        if "dkim=pass" in auth_results:
            result["dkim"] = "pass"
        elif "dkim=fail" in auth_results:
            result["dkim"] = "fail"

        if "dmarc=pass" in auth_results:
            result["dmarc"] = "pass"
        elif "dmarc=fail" in auth_results:
            result["dmarc"] = "fail"

        dkim_sig = str(
            msg.get("DKIM-Signature", "")
        )

        domain_match = re.search(
            r"\bd=([^;\s]+)",
            dkim_sig,
            re.IGNORECASE
        )

        selector_match = re.search(
            r"\bs=([^;\s]+)",
            dkim_sig,
            re.IGNORECASE
        )

        if domain_match:
            result["dkim_domain"] = (
                domain_match.group(1)
            )

        if selector_match:
            result["dkim_selector"] = (
                selector_match.group(1)
            )

    except Exception as e:
        print(f"[!] Unable to parse EML: {e}")

    return result


# EML Reporting
def report_eml(results):

    print_section("OBSERVED AUTHENTICATION RESULTS")

    print(f"SPF:   {colour_auth_result(results['spf'].upper())}")
    print(f"DKIM:  {colour_auth_result(results['dkim'].upper())}")
    print(f"DMARC: {colour_auth_result(results['dmarc'].upper())}")

    print()

    if results["dkim_domain"]:

        print("DKIM Details:")
        print(f"Signing Domain: {results['dkim_domain']}")
        print(f"Selector: {results['dkim_selector']}")

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

def print_summary(results):

    print_section("EMAIL SECURITY SUMMARY")

    for result in results:

        print(f"{result['control']:<12}{colour_assessment(result['assessment'])}")

    print()
    
    total_score = sum(r["score"] for r in results)
    max_score = sum(r["max_score"] for r in results)
    percentage = (total_score / max_score)

    if percentage == 1:
        overall = "EXCELLENT"

    elif percentage >= 0.75:
        overall = "GOOD"

    elif percentage >= 0.50:
        overall = "MODERATE"

    else:
        overall = "WEAK"

    print(f"Overall Security Posture: {colour_assessment(overall)} ({total_score}/{max_score})")
    print()


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(description = "Email security assessment tool")
    parser.add_argument("domain", help = "Target domain")
    parser.add_argument("--eml", help = "Path to EML file")
    parser.add_argument("--spoof", metavar = "EMAIL", help = "Recipient address for spoofing test")
    args = parser.parse_args()
    print_domain_header(args.domain)
    spf_record = get_spf_record(args.domain)
    dmarc_record = get_dmarc_record(args.domain)
    dkim_selector, dkim_record, dkim_found = check_dkim_dns(args.domain)
    mta_record = check_mta_sts(args.domain)
    mta_policy_raw = get_mta_sts_policy(args.domain)
    mta_policy = parse_mta_sts_policy(mta_policy_raw)

    results = [
        assess_spf(spf_record),
        assess_dmarc(dmarc_record),
        assess_dkim(dkim_selector, dkim_record, dkim_found),
        assess_mta_sts(mta_record, mta_policy),
    ]

    for result in results:
        print_assessment(result)

    print_summary(results)
    
    if args.eml:
        
        auth_results = parse_eml_file(args.eml)
        
        if auth_results["dkim_selector"]:
            dkim_selector, dkim_record, dkim_found = (check_dkim_dns(args.domain, auth_results["dkim_selector"]))
            results[2] = assess_dkim(dkim_selector, dkim_record, dkim_found)
            
        report_eml(auth_results)
        
    if args.spoof:
        
        spoof_result = perform_spoof_test(args.domain, args.spoof)
        report_spoof(spoof_result)


if __name__ == "__main__":
    main()