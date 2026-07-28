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
import tempfile
import os
from email import policy
from email.parser import BytesParser
from shutil import which

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

# Colour Definitions
COLOR_GREEN = "\033[0;32m"
COLOR_RED = "\033[0;31m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[0;36m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


# Control Definitions
CONTROL_DEFINITIONS = {

    "SPF":
        "Sender Policy Framework (SPF) is an email authentication mechanism "
        "that enables domain owners to explicitly identify the systems "
        "authorised to send email on behalf of the domain.",

    "DKIM":
        "DomainKeys Identified Mail (DKIM) is an email authentication "
        "mechanism that uses cryptographic signatures to allow receiving "
        "mail systems to verify that messages were authorised by the sending "
        "domain and were not modified in transit.",

    "DMARC":
        "Domain-based Message Authentication, Reporting and Conformance "
        "(DMARC) is an email authentication and policy framework that builds "
        "upon SPF and DKIM by instructing receiving organisations how to "
        "handle messages that fail authentication checks.",

    "MTA-STS":
        "Mail Transfer Agent Strict Transport Security (MTA-STS) is an "
        "email transport security mechanism that helps ensure SMTP "
        "communications are delivered over trusted TLS-encrypted channels "
        "and reduces the risk of downgrade attacks."
}


# Controls Overview Table Mapping
STATUS_MAP = {
    "SECURE": "Fully Implemented",
    "PRESENT": "Fully Implemented",
    "ACCEPTABLE": "Partially Implemented",
    "INSECURE": "Requires Review",
    "MISSING": "Not Implemented",
    "UNKNOWN": "Unable to Confirm"
}


# References
REFERENCES = {
    "cccs": "https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection",
    "ncsc": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing",
    "spf": "https://datatracker.ietf.org/doc/html/rfc7208",
    "dkim": "https://datatracker.ietf.org/doc/html/rfc6376",
    "dmarc": "https://datatracker.ietf.org/doc/html/rfc7489",
    "dmarc_org": "https://dmarc.org/resources/",
    "mta_sts": "https://datatracker.ietf.org/doc/html/rfc8461"
}


# Controls Overview Table Mapping
MTA_MAP = {
        "enforce": "Enforce",
        "testing": "Testing",
        "none": "Disabled"
    }


DMARC_MAP = {
    "reject": "Reject",
    "quarantine": "Quarantine",
    "none": "Monitoring"
}


# ------------------------------------------------------------
# Formatting
# ------------------------------------------------------------

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
    print(f"{COLOR_CYAN}{COLOR_BOLD}=== {title} ==={COLOR_RESET}\n")


def print_domain_header(domain):
    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{domain.upper()}{COLOR_RESET}\n")


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
# DKIM Assessment
# ------------------------------------------------------------

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google"]

def assess_dkim(selector, record, dkim_found, auth_results=None):

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

        if auth_results and auth_results.get("dkim", "").lower() == "pass":

            result["impact"] = ("The domain supports DKIM signature validation and "
                                "DKIM was observed to be functioning correctly within the supplied email sample.")

        elif auth_results and auth_results.get("dkim", "").lower() == "fail":

            result["impact"] = ("The domain supports DKIM signature validation; however, DKIM authentication failed within the supplied email sample.")

        else:

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

    result["tags"] = tags

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

        result["breakdown"].append("No MTA-STS record present")
        result["impact"] = ("SMTP delivery may rely solely on opportunistic TLS.")
        result["assessment"] = "MISSING"

        return result

    # DNS record exists
    result["breakdown"].append("Domain advertises support for MTA-STS")

    if policy["version"]:
        result["breakdown"].append(f"version={policy['version']} → Policy version")

    if policy["mode"]:
        result["breakdown"].append(f"mode={policy['mode']} → Enforcement mode")

    for mx in policy["mx"]:
        result["breakdown"].append(f"mx={mx} → Authorised mail server")

    if policy["max_age"]:
        result["breakdown"].append(f"max_age={policy['max_age']} → Policy cache duration")

    mode = policy.get("mode", "")

    if mode == "enforce":
        result["impact"] = ("Compatible mail servers should only deliver email over validated TLS connections.")
        result["assessment"] = "SECURE"
        result["score"] = 3

    elif mode == "testing":

        result["impact"] = ("TLS failures can be monitored, but the policy is not yet fully enforced.")
        result["assessment"] = "ACCEPTABLE"
        result["score"] = 2

    elif mode == "none":

        result["impact"] = ("MTA-STS is published but not enforced.")
        result["assessment"] = "INSECURE"
        result["score"] = 0

    else:

        result["impact"] = ("MTA-STS support is advertised, but the policy could not be retrieved or parsed successfully.")
        result["assessment"] = "PRESENT"
        result["score"] = 1

    result["policy"] = policy

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
    body = f"This email was generated as part of an authorised security assessment to validate SPF, DKIM, " \
        f"and DMARC enforcement for the {domain} domain."
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
        result["impact"] = ("No SMTP service was detected on localhost:25. Start a local SMTP relay (e.g. Postfix) "
            "before performing a spoofing assessment.")

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
        result["impact"] = ("The spoofed email was accepted by the local SMTP relay and submitted for delivery.\n"
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
    print(f"{result['impact']}")

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
            msg = BytesParser(policy=policy.default).parse(f)

        auth_results = str(msg.get("Authentication-Results", "")).lower()

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

        dkim_sig = str(msg.get("DKIM-Signature", ""))
        domain_match = re.search(r"\bd=([^;\s]+)",dkim_sig,re.IGNORECASE)
        selector_match = re.search(r"\bs=([^;\s]+)",dkim_sig,re.IGNORECASE)

        if domain_match:
            result["dkim_domain"] = (domain_match.group(1))

        if selector_match:
            result["dkim_selector"] = (selector_match.group(1))

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


# ------------------------------------------------------------
# Convert MSG to EML
# ------------------------------------------------------------

def convert_msg_to_eml(msg_file):

    if not which("msgconvert"):
        raise RuntimeError("msgconvert is not installed. Install libemail-outlook-message-perl.")

    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
        eml_path = temp_file.name

    result = subprocess.run(["msgconvert", "--outfile", eml_path, msg_file], capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError("Failed to convert MSG file using msgconvert.")
    return eml_path


# ------------------------------------------------------------
# Executive Summary
# ------------------------------------------------------------

def build_executive_summary(domain, results, auth_results=None):

    spf = results[0]
    dkim = results[1]
    dmarc = results[2]
    mta = results[3]

    authentication_strong = (
        spf["assessment"] in ["SECURE", "ACCEPTABLE"]
        and dkim["assessment"] == "PRESENT"
        and dmarc["assessment"] == "SECURE"
    )

    authentication_present = (
        spf["assessment"] != "MISSING"
        and dkim["assessment"] == "PRESENT"
        and dmarc["assessment"] != "MISSING"
    )

    authentication_working = (
        auth_results
        and auth_results.get("spf") == "pass"
        and auth_results.get("dkim") == "pass"
        and auth_results.get("dmarc") == "pass"
    )

    mta_missing = (mta["assessment"] == "MISSING")

    positive_controls = 0

    if spf["assessment"] in ["SECURE", "ACCEPTABLE"]:
        positive_controls += 1

    if dkim["assessment"] == "PRESENT":
        positive_controls += 1

    if dmarc["assessment"] == "SECURE":
        positive_controls += 1

    if mta["assessment"] == "PRESENT":
        positive_controls += 1

    text = []

    text.append(f"An email security review was performed against the {domain} domain to assess the implementation "
        "of industry-standard email authentication and transport security controls.")
    text.append("")

    if authentication_present:

        text.append("The assessment identified the implementation of SPF, DKIM and DMARC controls designed to "
            "reduce the risk of domain spoofing and improve confidence in the authenticity of email communications.")
        text.append("")

        if authentication_working:

            text.append("Successful SPF, DKIM and DMARC validation was observed within the supplied email "
                "sample, indicating that the authentication controls were functioning as intended.")
            text.append("")

    elif positive_controls == 0:

        text.append("The assessment did not identify SPF, DKIM, DMARC or MTA-STS controls. As a result, receiving organisations "
            "may have limited ability to verify the authenticity of email communications originating from the domain.")
        text.append("")

    if mta["assessment"] == "PRESENT":

        text.append("MTA-STS support was also identified, providing additional assurance that email communications are "
            "delivered over trusted encrypted channels and helping reduce exposure to SMTP downgrade attacks.")
        text.append("")

    elif mta["assessment"] == "MISSING" and positive_controls > 0:

        text.append("No MTA-STS policy was identified. This may reduce assurance that email communications are "
            "consistently delivered using trusted encrypted channels between mail systems.")
        text.append("")

    if positive_controls == 0:

        text.append("Overall, the domain demonstrated a weak email security posture. The absence of key "
            "email authentication and transport security controls increases exposure to spoofing, phishing "
            "and other forms of email-based attack.")

    elif authentication_strong and not mta_missing:

        text.append("Overall, the domain demonstrated a strong email security posture. The reviewed controls "
            "broadly aligned with recognised email security best practices and no significant weaknesses were identified.")

    elif authentication_strong and mta_missing:

        text.append("Overall, the domain demonstrated a generally mature email security posture with effective anti-spoofing "
            "controls, although opportunities were identified to further strengthen email transport security.")

    elif authentication_present and mta_missing:

        text.append("Overall, the domain demonstrated a generally mature email security posture with effective email "
            "authentication controls, although opportunities were identified to further strengthen email transport security.")

    else:

        text.append("Overall, the domain demonstrated a partially implemented email security posture. Whilst a number of "
            "controls were identified, additional improvements would further reduce exposure to spoofing, "
            "impersonation and email-based attacks.")

    return "\n".join(text)


# ------------------------------------------------------------
# Technical Commentary
# ------------------------------------------------------------

def build_commentary(domain, results, auth_results=None):

    spf = results[0]
    dkim = results[1]
    dmarc = results[2]
    mta = results[3]

    text = []

    text.append(f"A review of SPF, DKIM, DMARC and MTA-STS controls was performed against the {domain} domain to assess "
        "the implementation of email authentication and transport security controls.")
    text.append("")

    #----------------------------
    # Summary Table
    #----------------------------

    text.append("### Controls Overview")
    text.append("")

    # SPF value
    if "-all" in spf["raw"]:
        spf_config = "Hard Fail (-all)"

    elif "~all" in spf["raw"]:
        spf_config = "Soft Fail (~all)"

    elif "+all" in spf["raw"]:
        spf_config = "Permissive (+all)"

    else:
        spf_config = "Not Present"

    # DKIM value
    if dkim["assessment"] == "PRESENT":
        dkim_config = "Selector Present"
    else:
        dkim_config = "Unable to Confirm"

    # DMARC value
    policy = dmarc.get("tags", {}).get("p", "")
    dmarc_config = DMARC_MAP.get(policy, "Not Present")

    # MTA-STS value
    mode = mta.get("policy", {}).get("mode", "")
    mta_config = MTA_MAP.get(mode, "Not Present" if mta["assessment"] == "MISSING" else "Unknown")

    text.append("| Control | Configuration | Status |")
    text.append("|---------|---------------|--------|")
    text.append(f"| SPF | {spf_config} | {STATUS_MAP[spf['assessment']]} |")
    text.append(f"| DKIM | {dkim_config} | {STATUS_MAP[dkim['assessment']]} |")
    text.append(f"| DMARC | {dmarc_config} | {STATUS_MAP[dmarc['assessment']]} |")
    text.append(f"| MTA-STS | {mta_config} | {STATUS_MAP[mta['assessment']]} |")

    text.append("")

    #----------------------------
    # SPF
    #----------------------------

    text.append("### Sender Policy Framework (SPF)")
    text.append("")

    text.append(CONTROL_DEFINITIONS["SPF"])
    text.append("")

    if spf["assessment"] == "SECURE":

        text.append("The domain utilised a restrictive SPF configuration with a hard-fail enforcement policy, helping receiving mail systems identify "
            "authorised sending infrastructure and reject unauthorised sources.")

    elif spf["assessment"] == "ACCEPTABLE":

        text.append("The domain implemented SPF and identified authorised mail infrastructure. A soft-fail policy was observed. Whilst less "
            "restrictive than a hard-fail policy, SPF should still provide value when combined with DMARC enforcement.")

    elif spf["assessment"] == "INSECURE":

        text.append("The SPF record utilised a '+all' mechanism, effectively authorising any host on the Internet to send email on behalf of the domain. "
            "This significantly reduces the effectiveness of SPF as an anti-spoofing control and may increase exposure to email impersonation attacks.")

    elif spf["assessment"] == "MISSING":

        text.append("No SPF record was identified for the domain.")
        text.append("")
        text.append("As a result, receiving mail systems may be unable to reliably determine which hosts are "
            "authorised to send email on behalf of the domain.")

    if spf["assessment"] in ["SECURE", "ACCEPTABLE"]:

        includes = [x for x in spf["raw"].split() if x.startswith("include:")]

        if includes:

            text.append("")
            text.append("The following authorised sending services were identified:")

            for include in includes:
                text.append(f"- {include}")

            text.append("")

    if spf["assessment"] == "SECURE":

        text.append("This configuration helps reduce the risk of email spoofing and improves confidence in the authenticity of messages originating "
            "from the domain.")

    elif spf["assessment"] == "ACCEPTABLE":

        text.append("Although a soft-fail policy is less restrictive than a hard-fail configuration, the control should still provide value when combined "
            "with effective DMARC enforcement.")

    text.append("")

    #----------------------------
    # DKIM
    #----------------------------

    text.append("### DomainKeys Identified Mail (DKIM)")
    text.append("")

    text.append(CONTROL_DEFINITIONS["DKIM"])
    text.append("")

    if dkim["assessment"] == "PRESENT":

        if auth_results and auth_results.get("dkim") == "pass":

            text.append("DKIM support was identified through published DNS records and successful DKIM validation "
                "was observed within the supplied email sample.")
            text.append("")
            text.append("This demonstrates that outbound email messages were "
                "cryptographically signed and successfully validated by receiving mail systems.")

        else:

            text.append("DKIM support was identified through published DNS records and a corresponding public key was successfully "
                "retrieved. This enables receiving mail systems to validate message authenticity and integrity.")

    elif dkim["assessment"] == "UNKNOWN":

        text.append("DKIM support could not be confirmed through DNS and no suitable selector could be identified automatically. ")
        text.append("")
        text.append("As a result, assurance regarding the authenticity and integrity of outbound email communications may be reduced.")

    text.append("")

    #----------------------------
    # DMARC
    #----------------------------

    text.append("### Domain-based Message Authentication, Reporting and Conformance (DMARC)")
    text.append("")

    text.append(CONTROL_DEFINITIONS["DMARC"])
    text.append("")

    tags = dmarc.get("tags", {})

    if dmarc["assessment"] == "SECURE":

        text.append("The DMARC configuration was observed to:")
        text.append("")
        text.append("- Reject messages that fail authentication checks.")

    elif dmarc["assessment"] == "ACCEPTABLE":

        text.append("The DMARC configuration was observed to:")
        text.append("")
        text.append("- Treat messages that fail authentication checks as suspicious.")

    elif dmarc["assessment"] == "INSECURE":

        text.append("The DMARC configuration was observed to:")
        text.append("")
        text.append("- Monitor authentication failures without enforcing remediation actions.")

    elif dmarc["assessment"] == "MISSING":

        text.append("No DMARC policy was identified for the domain.")
        text.append("")
        text.append("As a result, receiving organisations are not provided with guidance on how to handle messages that fail "
            "SPF or DKIM validation, reducing the effectiveness of the domain's email authentication controls.")

    if dmarc["assessment"] != "MISSING":

        if "pct" in tags:
            text.append(f"- Apply the policy to {tags['pct']}% of received messages.")

        if "adkim" in tags:
            text.append(f"- Use {'strict' if tags['adkim'] == 's' else 'relaxed'} DKIM alignment.")

        if "aspf" in tags:
            text.append(f"- Use {'strict' if tags['aspf'] == 's' else 'relaxed'} SPF alignment.")

        if "rua" in tags:

            text.append("")
            text.append("DMARC aggregate reports were configured to be sent to:")
            text.append("")

            for address in tags["rua"].split(","):
                text.append(f"- {address.strip()}")

        if dmarc["assessment"] == "SECURE":

            text.append("This configuration helps reduce the risk of domain spoofing and provides "
                "greater confidence in the authenticity of messages originating from the domain.")
            text.append("")

        elif dmarc["assessment"] == "ACCEPTABLE":

            text.append("")
            text.append("Whilst less restrictive than a reject policy, this configuration still provides "
                "meaningful protection against spoofing and may help reduce the likelihood of fraudulent messages "
                "reaching end users.")
            text.append("")

        elif dmarc["assessment"] == "INSECURE":

            text.append("Although this configuration provides visibility through reporting, it does not provide "
                "meaningful protection against domain spoofing or email impersonation attacks.")
            text.append("")

    #----------------------------
    # MTA-STS
    #----------------------------

    text.append("### Mail Transfer Agent Strict Transport Security (MTA-STS)")
    text.append("")

    text.append(CONTROL_DEFINITIONS["MTA-STS"])
    text.append("")

    mta_policy = mta.get("policy", {})

    if mta["assessment"] == "SECURE":

        text.append("The MTA-STS configuration was observed to:")
        text.append("")

        text.append("- Operate in enforcement mode.")

        if mta_policy["max_age"]:
            text.append(f"- Cache policy information for {mta_policy['max_age']} seconds.")

        if mta_policy["mx"]:
            text.append("")
            text.append("The following authorised mail servers were identified:")

            for mx in mta_policy["mx"]:
                text.append(f"- {mx}")

        text.append("")

        text.append("This configuration helps reduce the risk of SMTP downgrade and adversary-in-the-middle "
            "attacks by ensuring email is delivered over trusted encrypted channels.")

    elif mta["assessment"] == "ACCEPTABLE":

        text.append("The MTA-STS configuration was observed to:")
        text.append("")

        text.append("- Operate in testing mode.")

        if mta_policy["max_age"]:
            text.append(f"- Cache policy information for {mta_policy['max_age']} seconds.")

        if mta_policy["mx"]:
            text.append("")
            text.append("The following authorised mail servers were identified:")

            for mx in mta_policy["mx"]:
                text.append(f"- {mx}")

        text.append("")
        text.append("Although not fully enforced, this demonstrates an intention to deploy stronger email "
            "transport security controls and provides visibility of potential TLS delivery issues.")

    elif mta["assessment"] == "INSECURE":

        text.append("The MTA-STS configuration was observed to:")
        text.append("")
        text.append("- Operate in a non-enforcing mode.")
        text.append("")
        text.append("As a result, email delivery may continue to rely on opportunistic TLS without providing "
            "meaningful protection against SMTP downgrade attacks.")

    elif mta["assessment"] == "PRESENT":

        text.append("An MTA-STS DNS record was identified; however, the associated policy could not be "
            "successfully retrieved or validated.")
        text.append("")
        text.append("Consequently, it was not possible to confirm that MTA-STS was operating as intended.")

    elif mta["assessment"] == "MISSING":

        text.append("No MTA-STS policy was identified for the domain.")
        text.append("")
        text.append("As a result, email delivery may rely solely on opportunistic TLS, reducing assurance that messages "
            "are delivered over trusted encrypted channels and increasing exposure to SMTP downgrade attacks.")

    return "\n".join(text)


# ------------------------------------------------------------
# Final Summary Table
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

    print(f"Overall Security Posture: {colour_posture(overall)} ({total_score}/{max_score})")
    print()


# ------------------------------------------------------------
# Recommendations
# ------------------------------------------------------------

def build_recommendations(domain, results):

    recommendations = []

    spf = results[0]
    dkim = results[1]
    dmarc = results[2]
    mta = results[3]

    all_missing = (
            spf["assessment"] == "MISSING"
            and dkim["assessment"] == "UNKNOWN"
            and dmarc["assessment"] == "MISSING"
            and mta["assessment"] == "MISSING"
        )

    if spf["assessment"] == "MISSING":
        recommendations.append("Publish an SPF record to explicitly define authorised mail sending infrastructure.")

    elif spf["assessment"] == "INSECURE":
        recommendations.append("Replace the '+all' SPF mechanism with a restrictive policy to prevent unauthorised systems from sending email on behalf of the domain.")

    if dkim["assessment"] == "UNKNOWN":
        recommendations.append("Configure DKIM signing and ensure the associated public key is published and publicly accessible.")

    if dmarc["assessment"] == "MISSING":
        recommendations.append("Implement DMARC with an appropriate reporting and enforcement policy to improve protection against spoofing and impersonation attacks.")

    if mta["assessment"] == "MISSING":
        recommendations.append("Deploy MTA-STS to strengthen SMTP transport security and reduce the risk of downgrade attacks.")

    if all_missing:
    
            text = ("The assessment identified the absence of SPF, DKIM, DMARC and MTA-STS controls. The organisation should implement a baseline "
                "email security framework consisting of these mechanisms to improve protection against spoofing, impersonation and insecure email transport.")
    
            text += ("\n\nFollowing implementation, the effectiveness of the controls should be validated through periodic reviews and testing to ensure "
                "they continue to operate as intended.")
    
            text += build_references(results)
    
            return text

    if not recommendations:
        text = ("Maintain the current email authentication and transport security controls. Periodic reviews should be conducted to ensure SPF, DKIM, DMARC and MTA-STS "
                "configurations remain aligned with business requirements and continue to operate effectively.")
        text += build_references(results)

        return text

    text = ("The identified weaknesses should be addressed to further strengthen the domain's email security posture:\n\n")

    for recommendation in recommendations:
        text += f"- {recommendation}\n"

    text += ("\nFollowing implementation, the effectiveness of the controls should be validated through periodic reviews and testing to ensure they continue to operate as intended.")
    text += build_references(results)

    return text

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

def build_references(results):

    refs = {"cccs", "ncsc"}

    spf = results[0]
    dkim = results[1]
    dmarc = results[2]
    mta = results[3]

    if spf["assessment"] in ["MISSING", "INSECURE", "UNKNOWN"]:
        refs.add("spf")

    if dkim["assessment"] in ["MISSING", "UNKNOWN"]:
        refs.add("dkim")

    if dmarc["assessment"] in ["MISSING", "UNKNOWN"]:
        refs.add("dmarc")
        refs.add("dmarc_org")

    if mta["assessment"] == "MISSING":
        refs.add("mta_sts")

    text = "\n\n### References\n\n"

    for ref in sorted(refs):
        url = REFERENCES[ref]
        text += f"- [{url}]({url})\n"

    return text


# ------------------------------------------------------------
# Markdown Export
# ------------------------------------------------------------

def export_markdown(domain, commentary, solution, results, auth_results=None):

    filename = f"{domain}.md"
    executive_summary = build_executive_summary(domain, results, auth_results)
    content = (
        f"## Executive Summary\n\n"
        f"{executive_summary}\n\n"
        f"## Technical Commentary\n\n"
        f"{commentary}\n\n"
        f"## Recommendations\n\n"
        f"{solution}\n"
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

    return filename


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    auth_results = None

    parser = argparse.ArgumentParser(description = "Email security assessment tool")
    parser.add_argument("domain", help = "Target domain")
    parser.add_argument("-E", "--email", help = "Path to EML or MSG file")
    parser.add_argument("--spoof", metavar = "EMAIL", help = "Recipient address for spoofing test (default ceo@<domain>)")

    args = parser.parse_args()

    print(f"\n[*] Retrieving DNS records and analysing email controls for the {args.domain} domain...\n")

    # Query the target records
    spf_record = get_spf_record(args.domain)
    dkim_selector, dkim_record, dkim_found = check_dkim_dns(args.domain)
    dmarc_record = get_dmarc_record(args.domain)
    mta_record = check_mta_sts(args.domain)
    mta_policy_raw = get_mta_sts_policy(args.domain)
    mta_policy = parse_mta_sts_policy(mta_policy_raw)

    # Parse the obtained records
    results = [
        assess_spf(spf_record),
        assess_dkim(dkim_selector, dkim_record, dkim_found, auth_results),
        assess_dmarc(dmarc_record),    
        assess_mta_sts(mta_record, mta_policy),
    ]

    # Parse email
    if args.email:

        email_file = args.email
        temp_eml = None

        # Convert MSG to EML
        try:
            if email_file.lower().endswith(".msg"):
                temp_eml = convert_msg_to_eml(email_file)
                email_file = temp_eml

            auth_results = parse_eml_file(email_file)
        
            if auth_results["dkim_selector"]:
                dkim_selector, dkim_record, dkim_found = (check_dkim_dns(args.domain, auth_results["dkim_selector"]))
                results[1] = assess_dkim(dkim_selector, dkim_record, dkim_found, auth_results)

        finally:
            if temp_eml and os.path.exists(temp_eml):
                os.remove(temp_eml)

    # Sections
    for result in results:
        print_assessment(result)

    # Final Summary Table
    print_summary(results)

    # Parsed Authentication Results
    if auth_results:
        report_eml(auth_results)

    # Perform Spoofing
    if args.spoof:
        spoof_result = perform_spoof_test(args.domain, args.spoof)
        report_spoof(spoof_result)

    # Generate the Stock Text for Markdown
    commentary = build_commentary(args.domain, results, auth_results)
    solution = build_recommendations(args.domain, results)

    # Generate Markdown
    md_file = export_markdown(args.domain, commentary, solution, results, auth_results)

    print()
    print(f"{COLOR_GREEN}[+] Assessment complete{COLOR_RESET}")
    print(f"{COLOR_GREEN}[+] Markdown Output   : {md_file}{COLOR_RESET}")
    print()


if __name__ == "__main__":
    main()