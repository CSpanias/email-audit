"""
Executive summary generation.

Builds a high-level narrative summarising the effectiveness of
the assessed email authentication and transport security controls.
"""


from email_audit.dns.dkim import weak_dkim_keys
from email_audit.reporting.definitions import load_definitions

TEXT = load_definitions("narratives")['executive_summary']


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------
def build_executive_summary(
        domain, 
        results, 
        auth_results=None, 
        spoof_result=None
    ):
    """
    Generate the executive summary section of the assessment report.

    The summary provides a non-technical overview of the identified
    email authentication and transport security controls, highlighting
    key strengths, weaknesses and areas for improvement.
    """

    spf = results[0]
    dkim = results[1]
    dmarc = results[2]
    mta = results[3]

    # Authentication results were present and could be evaluated
    authentication_validated = (
        auth_results
        and any(
            auth_results.get(x) in ["pass", "fail"]
            for x in ["spf", "dkim", "dmarc"]
        )
    )


    # Authentication controls broadly align with recognised industry practices
    authentication_strong = (
        spf["assessment"] in ["SECURE", "ACCEPTABLE"]
        and dkim["assessment"] == "PRESENT"
        and not weak_dkim_keys(dkim)
        and dmarc["assessment"] in ["SECURE", "ACCEPTABLE"]
    )

    # SPF, DKIM and DMARC controls were identified during the assessment
    authentication_present = (
        spf["assessment"] != "MISSING"
        and dkim["assessment"] == "PRESENT"
        and dmarc["assessment"] != "MISSING"
    )

    # SPF, DKIM and DMARC controls were identified and validated
    authentication_working = (
        authentication_validated
        and auth_results.get("spf") == "pass"
        and auth_results.get("dkim") == "pass"
        and auth_results.get("dmarc") == "pass"
    )

    # SPF, DKIM and DMARC controls were identified, but validation was 
    # unsuccessful
    authentication_failed = (
        authentication_validated
        and not authentication_working
    )

    text = []

    #---------------------------------------------------------------------------
    # Introduction (first paragraph)
    #---------------------------------------------------------------------------
    intro = (
        TEXT['build_executive_summary']['an_email_security_review_was_performed_against'].format(domain=domain)
    )

    text.append(intro)

    #---------------------------------------------------------------------------
    # Positive Controls (second paragraph)
    #---------------------------------------------------------------------------   
    
    # SPF, DKIM and DMARC controls were identified during the assessment
    if authentication_present:

        positive = (
            TEXT['build_executive_summary']['spf_dkim_and_dmarc_controls_were_identified']
        )

        # SPF, DKIM and DMARC controls were identified and validated
        if authentication_working:

            positive += (
                TEXT['build_executive_summary']['successful_validation_of_these_controls_was_observed']
            )

            # Authentication controls broadly align with recognised industry 
            # practices
            if authentication_strong:

                positive += (
                    TEXT['build_executive_summary']['collectively_these_controls_align_with_recognised_industry']
                )

        # SPF, DKIM and DMARC controls were identified, but validation was 
        # unsuccessful
        elif authentication_failed:

            positive += (
                TEXT['build_executive_summary']['validation_of_one_or_more_email_authentication']
            )

            if auth_results.get("spf") == "temperror":

                positive += (
                    TEXT['build_executive_summary']['specifically_spf_evaluation_resulted_in_a_temporary']
                )

        # SPF, DKIM and DMARC controls were identified; however, the supplied
        # email sample did not contain sufficient authentication results for
        # validation.
        else:

            positive += (
                TEXT['build_executive_summary']['email_authentication_controls_were_identified_however_the']
            )

    # Authentication controls were missing or inadequately implemented
    else:

        positive = (
            TEXT['build_executive_summary']['the_assessment_identified_weaknesses_affecting_the_domain']
        )

    text.append(positive)

    #-----------------------------------------------------------------------
    # Remaining risk (third paragraph)
    #-----------------------------------------------------------------------
    if spoof_result and spoof_result.get("successful"):

        text.append(
            TEXT['build_executive_summary']['despite_the_presence_of_email_authentication_controls'].format(domain=domain)
        )

    if (
        spf["assessment"] not in ["SECURE", "ACCEPTABLE"]
        and dkim["assessment"] != "PRESENT"
        and dmarc["assessment"] not in ["SECURE", "ACCEPTABLE"]
        and mta["assessment"] not in ["SECURE", "ACCEPTABLE"]
    ):
    
        text.append(
            TEXT['build_executive_summary']['the_assessment_identified_significant_weaknesses_affecting_the']
        )
    

    elif mta["assessment"] == "MISSING":

        text.append(
            TEXT['build_executive_summary']['mta_sts_missing']
        )

    elif mta["assessment"] == "UNKNOWN":

        text.append(
            TEXT['build_executive_summary']['mta_sts_unconfirmed']
        )

    elif mta["assessment"] in ["SECURE", "ACCEPTABLE"]:

        text.append(
            TEXT['build_executive_summary']['the_assessment_also_identified_effective_email_transport']
        )

    additional = load_definitions("narratives")["additional_checks"]
    for key in weak_dkim_keys(dkim):
        text.append(additional["weak_dkim"].format(
            selector=key["selector"], bits=key["key_bits"]
        ))
    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    if tls_rpt and tls_rpt["assessment"] != "PRESENT":
        text.append(additional[f"tls_rpt_{tls_rpt['assessment'].lower()}"].format(
            reason=tls_rpt["breakdown"][0] if tls_rpt["breakdown"] else ""
        ))

    #-----------------------------------------------------------------------
    # Conclusion (fourth paragraph)
    #-----------------------------------------------------------------------
    if (
        authentication_strong
        and authentication_working
        and mta["assessment"] in ["SECURE", "ACCEPTABLE"]
    ):

        text.append(
            TEXT['build_executive_summary']['mature_with_transport_security']
        )

    elif authentication_strong and authentication_working:

        text.append(
            TEXT['build_executive_summary']['mature_without_transport_security']
        )

    elif authentication_strong and authentication_failed:

        if spoof_result and spoof_result.get("successful"):

            text.append(
                TEXT['build_executive_summary']['authentication_failed_spoof_delivered']
            )

        else:

            text.append(
                TEXT['build_executive_summary']['authentication_failed']
            )

    elif authentication_present:

        text.append(
            TEXT['build_executive_summary']['overall_the_domain_demonstrated_a_generally_effective']
        )

    else:

        text.append(
            TEXT['build_executive_summary']['overall_the_domain_demonstrated_a_weak_email']
        )

    return "\n\n".join(text)