#!/usr/bin/env python3

"""
Email Security Audit Tool (PoC)

Author: Charalampos Spanias

Description:
Performs a DNS-based email security assessment and produces:

Raw Record
    ↓
Breakdown
    ↓
Security Impact
    ↓
Assessment
"""

import argparse
import subprocess
import re
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


# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def run_command(command):
    try:
        return subprocess.check_output(
            command,
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
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
    print(f"  {result['assessment']}")
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


def check_dkim_dns(domain):
    selectors = [
        "default",
        "selector1",
        "selector2",
        "google"
    ]

    for selector in selectors:
        output = run_command([
            "dig",
            "+short",
            f"{selector}._domainkey.{domain}",
            "TXT"
        ])

        if output:
            return selector, output

    return "", ""


# ------------------------------------------------------------
# SPF Assessment
# ------------------------------------------------------------

def assess_spf(record):

    result = {
        "control": "SPF",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": ""
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
        result["max_score"] = 3

    elif "~all" in elements:

        result["impact"] = ("Unauthorised senders may still be accepted by some recipients.")
        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2
        result["max_score"] = 3

    elif "+all" in elements:

        result["impact"] = ("Any sender is effectively authorised to send email.")
        result["assessment"] = "INSECURE"
        result["score"] = 0
        result["max_score"] = 3

    else:

        result["impact"] = ("SPF enforcement behaviour could not be clearly determined.")
        result["assessment"] = "UNKNOWN"
        result["score"] = 0
        result["max_score"] = 3

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
        "assessment": ""
    }

    if not record:

        result["breakdown"].append("No DMARC record present")
        result["impact"] = ("Receiving servers are not given any policy for handling authentication failures.")
        result["assessment"] = "MISSING"
        result["score"] = 0
        result["max_score"] = 3

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
        result["max_score"] = 3

    elif policy == "quarantine":

        result["impact"] = ("Messages failing authentication should normally be treated as suspicious.")
        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2
        result["max_score"] = 3

    elif policy == "none":

        result["impact"] = ("Authentication failures are monitored but not enforced.")
        result["assessment"] = "INSECURE"
        result["score"] = 0
        result["max_score"] = 3

    else:

        result["impact"] = ("Policy could not be clearly determined.")
        result["assessment"] = "UNKNOWN"
        result["score"] = 0
        result["max_score"] = 3

    return result


# ------------------------------------------------------------
# DKIM Assessment
# ------------------------------------------------------------

def assess_dkim(selector, record):

    result = {
        "control": "DKIM",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": ""
    }

    if not record:

        result["breakdown"].append("No common selector detected")
        result["impact"] = ("DKIM support could not be confirmed through DNS.")
        result["assessment"] = "UNKNOWN"
        result["score"] = 0
        result["max_score"] = 1

        return result

    result["breakdown"].append(f"selector={selector} → DNS lookup location")
    result["breakdown"].append("Public key present in DNS")
    result["impact"] = ("The domain supports DKIM signature validation. Actual implementation still requires inspection of a received email.")
    result["assessment"] = "PRESENT"
    result["score"] = 1
    result["max_score"] = 1

    return result


# ------------------------------------------------------------
# MTA-STS Assessment
# ------------------------------------------------------------

def assess_mta_sts(record):

    result = {
        "control": "MTA-STS",
        "raw": record,
        "breakdown": [],
        "impact": "",
        "assessment": ""
    }

    if not record:

        result["breakdown"].append("No MTA-STS record present")
        result["impact"] = ("SMTP delivery may rely solely on opportunistic TLS.")
        result["assessment"] = "MISSING"
        result["score"] = 0
        result["max_score"] = 1

        return result

    result["breakdown"].append("Domain advertises support for MTA-STS")
    result["impact"] = ("Compatible mail servers can enforce secure SMTP delivery.")
    result["assessment"] = "PRESENT"
    result["score"] = 1
    result["max_score"] = 1

    return result


# ------------------------------------------------------------
# EML Parsing
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# EML Reporting
# ------------------------------------------------------------

def report_eml(results):

    print_section(
        "OBSERVED AUTHENTICATION RESULTS"
    )

    print(f"SPF:   {results['spf'].upper()}")
    print(f"DKIM:  {results['dkim'].upper()}")
    print(f"DMARC: {results['dmarc'].upper()}")

    print()

    if results["dkim_domain"]:

        print("DKIM Details:")

        print(
            f"  Signing Domain: "
            f"{results['dkim_domain']}"
        )

        print(
            f"  Selector: "
            f"{results['dkim_selector']}"
        )

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

def print_summary(results):

    print_section("EMAIL SECURITY SUMMARY")

    for result in results:

        print(
            f"{result['control']:<10}"
            f"{result['assessment']}"
        )

    print()
    

    total_score = sum(
        r["score"]
        for r in results
    )

    max_score = sum(
        r["max_score"]
        for r in results
    )

    percentage = (
        total_score / max_score
    )

    if percentage == 1:
        overall = "EXCELLENT"

    elif percentage >= 0.75:
        overall = "GOOD"

    elif percentage >= 0.50:
        overall = "MODERATE"

    else:
        overall = "WEAK"

    print(
        f"Overall Security Posture: "
        f"{overall} ({total_score}/{max_score})"
    )

    print()


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(description = "Email security assessment tool")
    parser.add_argument("domain", help = "Target domain")
    parser.add_argument("--eml", help = "Path to EML file")
    args = parser.parse_args()
    print_domain_header(args.domain)
    spf_record = get_spf_record(args.domain)
    dmarc_record = get_dmarc_record(args.domain)
    dkim_selector, dkim_record = (check_dkim_dns(args.domain))
    mta_record = check_mta_sts(args.domain)

    results = [
        assess_spf(spf_record),
        assess_dmarc(dmarc_record),
        assess_dkim(dkim_selector, dkim_record),
        assess_mta_sts(mta_record),
    ]

    for result in results:
        print_assessment(result)

    print_summary(results)
    
    if args.eml:
        
        eml_results = parse_eml_file(args.eml)
        report_eml(eml_results)


if __name__ == "__main__":
    main()