#!/usr/bin/env python3

import sys
import json

if len(sys.argv) < 2:
    print("Usage: email-report.py <logfile>")
    sys.exit(1)

log_file = sys.argv[1]


# -------------------------
# Extract JSON blocks
# -------------------------
def extract_json_blocks(file_path):
    blocks = []
    capture = False
    buffer = ""

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()

            if line == "--- JSON OUTPUT START ---":
                capture = True
                buffer = ""
                continue

            if line == "--- JSON OUTPUT END ---":
                capture = False
                try:
                    blocks.append(json.loads(buffer))
                except json.JSONDecodeError:
                    pass
                continue

            if capture:
                buffer += line

    return blocks


# -------------------------
# Generate report
# -------------------------
def generate_report(data):
    domain = data.get("domain", "unknown")
    spf = data.get("spf", "")
    dmarc_policy = data.get("dmarc_policy", "missing")
    mta_sts = data.get("mta_sts", False)
    spf_strict = data.get("spf_strict", False)
    dkim_present = data.get("dkim_present", False)
    spoof = data.get("spoof_attempt", "unknown")

    print(f"\n## **{domain}**\n")

    # Intro
    print("The domain was assessed to determine the effectiveness of its email security configuration, including SPF, DKIM, DMARC, and transport security controls.\n")

    # SPF
    if not spf:
        print("SPF was not configured, meaning there was no mechanism to define authorised sending sources for the domain.\n")
    elif spf_strict:
        print("SPF was configured with a strict policy (-all), ensuring that unauthorised sending sources were explicitly rejected.\n")
    else:
        print("SPF was configured; however, it utilised a softfail policy (~all), which did not enforce strict rejection of unauthorised senders.\n")

    # DKIM
    if dkim_present:
        print("DKIM appeared to be implemented, indicating that outbound email messages could be cryptographically signed and validated by receiving systems.\n")
    else:
        print("DKIM could not be identified using common selectors. This may indicate it was not implemented, or that non-standard selectors were in use.\n")

    # DMARC
    if dmarc_policy == "reject":
        print("DMARC was enforced with a policy of 'reject', providing strong protection against spoofing and impersonation attempts.\n")
    elif dmarc_policy == "quarantine":
        print("DMARC was configured with a 'quarantine' policy, providing moderate protection by directing unauthenticated messages to spam folders.\n")
    elif dmarc_policy == "none":
        print("DMARC was configured with a monitoring-only policy (p=none), meaning no enforcement was applied to unauthenticated messages.\n")
    else:
        print("DMARC was not configured, meaning no domain-level enforcement existed to prevent spoofing.\n")

    # MTA-STS
    if mta_sts:
        print("MTA-STS was implemented, ensuring that email delivery was restricted to trusted servers over encrypted (TLS) connections.\n")
    else:
        print("MTA-STS was not implemented, meaning SMTP transport security was not explicitly enforced.\n")

    # Spoofing
    if spoof == "attempted":
        print("A practical spoofing test was performed. The spoofed message was accepted by the local mail transfer agent and queued for delivery. This does not confirm whether the message would be delivered or rejected by the recipient environment.\n")
    else:
        print("No practical spoofing test was performed as part of this assessment.\n")

    # Overall assessment
    if dmarc_policy == "reject" and spf_strict:
        posture = "a strong email authentication posture"
    elif dmarc_policy in ["quarantine", "reject"]:
        posture = "a moderate level of email security"
    else:
        posture = "weak or insufficient email security controls"

    print(f"**Overall, the domain demonstrated {posture}.**\n")

    # Recommendations
    print("### Recommendations\n")

    if not spf:
        print("- Implement an SPF record to define authorised sending sources.")
    elif not spf_strict:
        print("- Enforce a strict SPF policy (-all) to prevent unauthorised use of the domain.")

    if not dkim_present:
        print("- Ensure DKIM is properly implemented and documented, including known selectors.")

    if dmarc_policy in ["none", "missing"]:
        print("- Implement DMARC with an enforcement policy (p=reject) to mitigate spoofing.")
    elif dmarc_policy != "reject":
        print("- Consider enforcing DMARC with p=reject for stronger protection.")

    if not mta_sts:
        print("- Consider implementing MTA-STS to enforce secure SMTP transport.")

    print("\n### References\n")
    print("https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection")

    print("\n---\n")

# -------------------------
# Main
# -------------------------
json_blocks = extract_json_blocks(log_file)

if not json_blocks:
    print("[-] No JSON data found in log")
    sys.exit(1)

for block in json_blocks:
    generate_report(block)