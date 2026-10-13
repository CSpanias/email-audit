"""
Remediation guidance and reference generation.

Builds remediation recommendations and supporting references based on
identified weaknesses in the assessed email security controls.
"""

from email_audit.constants import REFERENCES


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------
def build_references(results, auth_results=None, spoof_result=None):
    """
    Generate a list of references relevant to the identified findings.

    References are selected dynamically based on the assessed
    controls and included within the generated remediation section.
    """

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

    if mta["assessment"] in ["MISSING", "UNKNOWN"]:
        refs.add("mta_sts")

    if auth_results:

        if auth_results.get("spf") == "temperror":
            refs.add("spf")

    text = "\n\n### References\n\n"

    for ref in sorted(refs):
        url = REFERENCES[ref]
        text += f"- [{url}]({url})\n"

    return text


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------
def build_recommendations(results, auth_results=None, spoof_result=None):
    """
    Generate remediation recommendations for identified weaknesses.

    Recommendations are tailored to the assessment results and
    provide prioritised guidance for improving the organisation's
    email authentication and transport security posture.
    """

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
        recommendations.append(
            "Publish an SPF record to explicitly define authorised mail "
            "sending infrastructure."
        )

    elif spf["assessment"] == "INSECURE":
        recommendations.append(
            "Replace the '+all' SPF mechanism with a restrictive policy to "
            "prevent unauthorised systems from sending email on behalf of the "
            "domain."
        )

    if dkim["assessment"] == "UNKNOWN":
        recommendations.append(
            "Configure DKIM signing and ensure the associated public key is"
            " published and publicly accessible."
        )

    if dmarc["assessment"] == "MISSING":
        recommendations.append(
            "Implement DMARC with an appropriate reporting and enforcement "
            "policy to improve protection against spoofing and impersonation "
            "attacks."
        )

    if mta["assessment"] == "MISSING":
        recommendations.append(
            "Deploy MTA-STS to strengthen SMTP transport security and reduce "
            "the risk of downgrade attacks."
        )

    elif mta["assessment"] == "UNKNOWN":
        recommendations.append(
            "Review the published MTA-STS configuration and ensure the policy "
            "can be successfully retrieved and validated by external systems."
        )

    # -----------------------------------------------------------------------
    # Authentication Validation
    # -----------------------------------------------------------------------
    if auth_results:

        if auth_results.get("spf") == "temperror":

            recommendations.append(
                "Investigate the cause of SPF processing failures and review "
                "the published SPF record for excessive complexity, DNS "
                "lookup limits, nested include mechanisms or DNS "
                "resolution issues."
            )

            recommendations.append(
                "Validate that the SPF policy can be successfully processed "
                "by receiving mail systems and that the effective number of "
                "DNS lookups remains within RFC limitations."
            )

    # --------------------------------------------------------------------------
    # Controlled Spoofing Assessment
    # --------------------------------------------------------------------------
    if spoof_result:

        if spoof_result.get("successful"):

            recommendations.append(
                "Investigate the conditions that allowed successful domain "
                "spoofing during testing and identify any weaknesses affecting "
                "the effectiveness of the implemented email authentication "
                "controls."
            )

            recommendations.append(
                "Review SPF, DKIM and DMARC configurations and validate that "
                "email authentication controls operate as intended under "
                "real-world conditions."
            )


    # --------------------------------------------------------------------------
    # No Controls at All
    # --------------------------------------------------------------------------
    if all_missing:
    
            text = (
                "The assessment identified the absence of SPF, DKIM, DMARC "
                "and MTA-STS controls. The organisation should implement a "
                "baseline email security framework consisting of these "
                "mechanisms to improve protection against spoofing, "
                "impersonation and insecure email transport."
            )
    
            text += (
                "\n\nFollowing implementation, the effectiveness of the "
                "controls should be validated through periodic reviews and "
                "testing to ensure they continue to operate as intended."
            )
    
            text += build_references(results, auth_results, spoof_result)
    
            return text

    if not recommendations:
        text = (
            "Maintain the current email authentication and transport security "
            "controls. Periodic reviews should be conducted to ensure SPF, "
            "DKIM, DMARC and MTA-STS configurations remain aligned with "
            "business requirements and continue to operate effectively."
        )

        text += build_references(results, auth_results, spoof_result)

        return text

    text = (
        "The identified weaknesses should be addressed to further strengthen "
        "the domain's email security posture:\n\n"
    )

    for recommendation in recommendations:
        text += f"- {recommendation}\n"

    text += (
        "\nFollowing implementation, the effectiveness of the controls should "
        "be validated through periodic reviews and testing to ensure they "
        "continue to operate as intended."
    )

    text += build_references(results, auth_results, spoof_result)

    return text