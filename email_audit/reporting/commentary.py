"""
Technical commentary generation.

Builds the technical commentary section of the assessment report,
including control-specific observations and supporting evidence.
"""


from email_audit.constants import (
    CONTROL_DEFINITIONS,
    DMARC_MAP,
    MTA_MAP,
)


def build_commentary(domain, results, auth_results=None, spoof_result=None):
    """
    Generate the technical commentary section of the assessment report.
    """

    spf = results[0]
    dkim = results[1]
    dmarc = results[2]
    mta = results[3]

    text = []

    text.append(
            "A review of SPF, DKIM, DMARC and MTA-STS controls was performed "
            f"against the {domain} domain to assess the implementation of email "
            "authentication and transport security controls."
        )
    text.append("")

    _build_summary_table(text, spf, dkim, dmarc, mta)
    _build_spf_commentary(text, spf, auth_results)
    _build_dkim_commentary(text, dkim, auth_results)
    _build_dmarc_commentary(text, dmarc)
    _build_mta_sts_commentary(text, mta)
    _build_spoofing_commentary(text, spoof_result)

    return "\n".join(text)


# ---------------------------------------------------------------------------
# Controls Configuration Summary
# ---------------------------------------------------------------------------
def _build_summary_table(text, spf, dkim, dmarc, mta):
    """
    Build the controls configuration summary table.
    """
    
    text.append("### Controls Configuration Summary")
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

    text.append("| Control  | Configuration  |")
    text.append("|----------|----------------|")
    text.append(f"| SPF     | {spf_config}   |")
    text.append(f"| DKIM    | {dkim_config}  |")
    text.append(f"| DMARC   | {dmarc_config} |")
    text.append(f"| MTA-STS | {mta_config}   |")

    text.append("")


# ---------------------------------------------------------------------------
# SPF Commentary
# ---------------------------------------------------------------------------
def _build_spf_commentary(text, spf, auth_results):
    """
    Build the SPF technical commentary section.
    """

    text.append("### Sender Policy Framework (SPF)")
    text.append("")

    text.append(CONTROL_DEFINITIONS["SPF"])
    text.append("")

    if spf["assessment"] == "SECURE":

        text.append(
            "The domain implemented SPF using a restrictive hard-fail "
            "enforcement policy (-all), helping receiving mail systems "
            "identify authorised sending infrastructure and reject "
            "unauthorised sources."
        )

    elif spf["assessment"] == "ACCEPTABLE":

        text.append(
            "The domain implemented SPF and identified authorised mail "
            "infrastructure. A soft-fail policy (~all) was observed. Whilst "
            "less restrictive than a hard-fail policy, SPF should still "
            "provide value when combined with DMARC enforcement."
        )

    elif spf["assessment"] == "INSECURE":

        text.append(
            "The SPF record utilised the permissive '+all' mechanism, "
            "effectively authorising any host on the Internet to send email on "
            "behalf of the domain. This significantly reduces the "
            "effectiveness of SPF as an anti-spoofing control and may increase "
            "exposure to email impersonation attacks."
        )

    elif spf["assessment"] == "MISSING":

        text.append("No SPF record was identified for the domain.")
        text.append("")
        text.append(
            "As a result, receiving mail systems may be unable to reliably "
            "determine which hosts are authorised to send email on behalf of "
            "the domain."
        )

    if spf["assessment"] in ["SECURE", "ACCEPTABLE"]:

        elements = spf["raw"].split()

        includes = [
            x.replace("include:", "")
            for x in elements
            if x.startswith("include:")
        ]

        ips = [
            x.replace("ip4:", "").replace("ip6:", "")
            for x in elements
            if x.startswith(("ip4:", "ip6:"))
        ]

        if includes:

            text.append("")
            text.append(
                "The following authorised sending services were identified:"
            )
            text.append("")

            for provider in includes:
                text.append(f"- {provider}")

        if ips:

            text.append("")
            text.append(
                "The following authorised IP addresses were identified:"
            )
            text.append("")

            for ip in ips:
                text.append(f"- {ip}")

        text.append("")

    if auth_results:

        spf_result = auth_results.get("spf")

        if spf_result == "temperror":

            text.append(
                "Authentication results extracted from the supplied "
                "email sample indicated an SPF temporary processing "
                "error (temperror)."
            )

            text.append("")

            text.append(
                "This suggests that receiving mail systems were unable "
                "to successfully complete SPF evaluation. A controlled "
                "spoofing assessment further demonstrated that a spoofed "
                "email claiming to originate from the target domain could "
                "be successfully delivered, indicating that the intended "
                "anti-spoofing protections may not be operating effectively "
                "in practice."
            )

            text.append("")

        elif spf_result == "fail":

            text.append(
                "Authentication results extracted from the supplied "
                "email sample indicated that SPF validation failed."
            )

            text.append("")

            text.append(
                "This suggests that the observed email message was not "
                "authorised by the published SPF policy."
            )

            text.append("")


    text.append("")


# ---------------------------------------------------------------------------
# DKIM Commentary
# ---------------------------------------------------------------------------
def _build_dkim_commentary(text, dkim, auth_results):
    """
    Build the DKIM technical commentary section.
    """

    text.append("### DomainKeys Identified Mail (DKIM)")
    text.append("")

    text.append(CONTROL_DEFINITIONS["DKIM"])
    text.append("")

    if dkim["assessment"] == "PRESENT":

        if auth_results and auth_results.get("dkim") == "pass":

            text.append(
                "DKIM support was identified through published DNS records "
                "and successful DKIM validation was observed within the "
                "supplied email sample."
            )
            text.append("")

            text.append(
                "This demonstrates that outbound email messages were "
                "cryptographically signed and successfully validated by "
                "receiving mail systems."
            )

        else:

            text.append(
                "DKIM support was identified through published DNS records "
                "and a corresponding public key was successfully retrieved. "
                "This enables receiving mail systems to validate message "
                "authenticity and integrity."
            )

    elif dkim["assessment"] == "UNKNOWN":

        text.append(
            "DKIM support could not be confirmed through DNS and no suitable "
            "selector could be identified automatically. "
        )
        text.append("")

        text.append(
            "As a result, assurance regarding the authenticity and integrity "
            "of outbound email communications may be reduced."
        )

    text.append("")


# ---------------------------------------------------------------------------
# DMARC Commentary
# ---------------------------------------------------------------------------
def _build_dmarc_commentary(text, dmarc):
    """
    Build the DMARC technical commentary section.
    """

    text.append(
        "### Domain-based Message Authentication, Reporting and "
        "Conformance (DMARC)"
    )
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

        text.append(
            "- Treat messages that fail authentication checks as suspicious."
        )

    elif dmarc["assessment"] == "INSECURE":

        text.append("The DMARC configuration was observed to:")
        text.append("")
        text.append(
            "- Monitor authentication failures without enforcing remediation "
            "actions."
        )

    elif dmarc["assessment"] == "MISSING":

        text.append("No DMARC policy was identified for the domain.")
        text.append("")

        text.append(
            "As a result, receiving organisations are not provided with "
            "guidance on how to handle messages that fail SPF or DKIM "
            "validation, reducing the effectiveness of the domain's email "
            "authentication controls."
        )

    if dmarc["assessment"] != "MISSING":

        if "pct" in tags:
            text.append(
                f"- Apply the policy to {tags['pct']}% of received messages."
            )

        if "adkim" in tags:
            text.append(
                f"- Use {'strict' if tags['adkim'] == 's' else 'relaxed'} "
                "DKIM alignment."
            )

        if "aspf" in tags:
            text.append(
                f"- Use {'strict' if tags['aspf'] == 's' else 'relaxed'} "
                "SPF alignment."
            )

        if "rua" in tags:

            text.append("")
            text.append(
                "DMARC aggregate reports were configured to be sent to:"
            )
            text.append("")

            for address in tags["rua"].split(","):
                address = address.strip().replace("mailto:", "")
                text.append(f"- {address.strip()}")

        if dmarc["assessment"] == "SECURE":

            text.append("")
            text.append(
                "This configuration helps reduce the risk of domain spoofing "
                "and provides greater confidence in the authenticity of "
                "messages originating from the domain."
            )
            text.append("")

        elif dmarc["assessment"] == "ACCEPTABLE":

            text.append("")
            text.append(
                "Whilst less restrictive than a reject policy, this "
                "configuration still provides meaningful protection against "
                "spoofing and may help reduce the likelihood of fraudulent "
                "messages reaching end users."
            )
            text.append("")

        elif dmarc["assessment"] == "INSECURE":

            text.append(
                "Although this configuration provides visibility through "
                "reporting, it does not provide meaningful protection against "
                "domain spoofing or email impersonation attacks."
            )
            text.append("")


# ---------------------------------------------------------------------------
# MTA-STS Commentary
# ---------------------------------------------------------------------------
def _build_mta_sts_commentary(text, mta):
    """
    Build the MTA-STS technical commentary section.
    """

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
            text.append(
                f"- Cache policy information for {mta_policy['max_age']} "
                "seconds."
            )

        if mta_policy["mx"]:
            text.append("")
            text.append(
                "The following authorised mail servers were identified:"
            )

            for mx in mta_policy["mx"]:
                text.append(f"- {mx}")

        text.append("")

        text.append(
            "This configuration helps reduce the risk of SMTP downgrade and "
            "adversary-in-the-middle attacks by ensuring email is delivered "
            "over trusted encrypted channels."
        )

    elif mta["assessment"] == "ACCEPTABLE":

        text.append("The MTA-STS configuration was observed to:")
        text.append("")

        text.append("- Operate in testing mode.")

        if mta_policy["max_age"]:
            text.append(
                f"- Cache policy information for {mta_policy['max_age']} "
                "seconds."
            )

        if mta_policy["mx"]:
            text.append("")
            text.append(
                "The following authorised mail servers were identified:"
            )

            for mx in mta_policy["mx"]:
                text.append(f"- {mx}")

        text.append("")
        text.append(
            "Although not fully enforced, this demonstrates an intention to "
            "deploy stronger email transport security controls and provides "
            "visibility of potential TLS delivery issues."
        )

    elif mta["assessment"] == "INSECURE":

        text.append("The MTA-STS configuration was observed to:")
        text.append("")
        text.append("- Operate in a non-enforcing mode.")
        text.append("")
        text.append(
            "As a result, email delivery may continue to rely on opportunistic"
            " TLS without providing meaningful protection against SMTP " \
            "downgrade attacks."
        )

    elif mta["assessment"] == "UNKNOWN":

        text.append(
            "An MTA-STS DNS record was also identified; however, the "
            "associated policy could not be successfully retrieved or "
            "validated. Consequently, it was not possible to confirm that "
            "MTA-STS was operating as intended."
        )

    elif mta["assessment"] == "MISSING":

        text.append("No MTA-STS policy was identified for the domain.")
        text.append("")
        text.append(
            "As a result, email delivery may rely solely on opportunistic TLS, "
            "reducing assurance that messages are delivered over trusted "
            "encrypted channels and increasing exposure to SMTP downgrade "
            "attacks."
        )

    text.append("")


# ---------------------------------------------------------------------------
# Controlled Spoofing Assessment
# ---------------------------------------------------------------------------
def _build_spoofing_commentary(text, spoof_result):
    """
    Build the spoofing assessment commentary section.
    """

    if not spoof_result:
        return

    text.append("### Controlled Spoofing Assessment")
    text.append("")

    if spoof_result.get("successful"):

        text.append(
            "A controlled spoofing assessment identified that an email "
            "claiming to originate from the target domain could be "
            "successfully generated and delivered during testing."
        )

        text.append("")

        text.append(
            "Although email authentication controls were present, "
            "testing demonstrated that these controls did not "
            "effectively prevent delivery of a spoofed message."
        )

    else:

        text.append(
            "Testing did not identify evidence that a spoofed "
            "email could be successfully delivered."
        )

    text.append("")