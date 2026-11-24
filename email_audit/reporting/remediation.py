"""
Remediation guidance and reference generation.

Builds remediation recommendations and supporting references based on
identified weaknesses in the assessed email security controls.
"""

from email_audit.dns.dkim import weak_dkim_keys
from email_audit.reporting.definitions import load_definitions

TEXT = load_definitions("narratives")['remediation']
REFERENCES = load_definitions("reference")["references"]
ADDITIONAL = load_definitions("narratives")["additional_checks"]

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
    if weak_dkim_keys(dkim):
        refs.add("dkim_crypto")

    if dmarc["assessment"] in ["MISSING", "UNKNOWN"]:
        refs.add("dmarc")
        refs.add("dmarc_org")

    if mta["assessment"] in ["MISSING", "UNKNOWN"]:
        refs.add("mta_sts")
    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    if tls_rpt and tls_rpt["assessment"] in ["MISSING", "INVALID"]:
        refs.add("tls_rpt")

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
    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    additional_recommendations = []
    for key in weak_dkim_keys(dkim):
        additional_recommendations.append(
            ADDITIONAL["weak_dkim_recommendation"].format(selector=key["selector"])
        )
    if tls_rpt and tls_rpt["assessment"] in ["MISSING", "INVALID"]:
        additional_recommendations.append(
            ADDITIONAL[f"tls_rpt_{tls_rpt['assessment'].lower()}_recommendation"]
        )

    all_missing = (
            spf["assessment"] == "MISSING"
            and dkim["assessment"] == "UNKNOWN"
            and dmarc["assessment"] == "MISSING"
            and mta["assessment"] == "MISSING"
        )

    if spf["assessment"] == "MISSING":
        recommendations.append(
            TEXT['build_recommendations']['publish_an_spf_record_to_explicitly_define']
        )

    elif spf["assessment"] == "INSECURE":
        recommendations.append(
            TEXT['build_recommendations']['replace_the_all_spf_mechanism_with_a']
        )

    if dkim["assessment"] == "UNKNOWN":
        recommendations.append(
            TEXT['build_recommendations']['configure_dkim_signing_and_ensure_the_associated']
        )

    if dmarc["assessment"] == "MISSING":
        recommendations.append(
            TEXT['build_recommendations']['implement_dmarc_with_an_appropriate_reporting_and']
        )

    if mta["assessment"] == "MISSING":
        recommendations.append(
            TEXT['build_recommendations']['deploy_mta_sts_to_strengthen_smtp_transport']
        )

    elif mta["assessment"] == "UNKNOWN":
        recommendations.append(
            TEXT['build_recommendations']['review_the_published_mta_sts_configuration_and']
        )

    # -----------------------------------------------------------------------
    # Authentication Validation
    # -----------------------------------------------------------------------
    if auth_results:

        if auth_results.get("spf") == "temperror":

            recommendations.append(
                TEXT['build_recommendations']['investigate_the_cause_of_spf_processing_failures']
            )

            recommendations.append(
                TEXT['build_recommendations']['validate_that_the_spf_policy_can_be']
            )

    # --------------------------------------------------------------------------
    # Controlled Spoofing Assessment
    # --------------------------------------------------------------------------
    if spoof_result:

        if spoof_result.get("successful"):

            recommendations.append(
                TEXT['build_recommendations']['investigate_the_conditions_that_allowed_successful_domain']
            )

            recommendations.append(
                TEXT['build_recommendations']['review_spf_dkim_and_dmarc_configurations_and']
            )

    recommendations.extend(additional_recommendations)

    # --------------------------------------------------------------------------
    # No Controls at All
    # --------------------------------------------------------------------------
    if all_missing:
    
            text = (
                TEXT['build_recommendations']['the_assessment_identified_the_absence_of_spf']
            )
            if additional_recommendations:
                text += "\n\n" + "\n".join(f"- {item}" for item in additional_recommendations)
    
            text += (
                TEXT['build_recommendations']['follow_up_after_paragraph']
            )
    
            text += build_references(results, auth_results, spoof_result)
    
            return text

    if not recommendations:
        text = (
            TEXT['build_recommendations']['maintain_the_current_email_authentication_and_transport']
        )

        text += build_references(results, auth_results, spoof_result)

        return text

    text = (
        TEXT['build_recommendations']['the_identified_weaknesses_should_be_addressed_to']
    )

    for recommendation in recommendations:
        text += f"- {recommendation}\n"

    text += (
        TEXT['build_recommendations']['follow_up_after_list']
    )

    text += build_references(results, auth_results, spoof_result)

    return text