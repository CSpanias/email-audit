"""
Executive summary generation.

Builds a high-level narrative summarising the effectiveness of
the assessed email authentication and transport security controls.
"""


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

    # Experimental scoring
    configured_controls = 0

    if spf["assessment"] in ["SECURE", "ACCEPTABLE"]:
        configured_controls += 1

    if dkim["assessment"] == "PRESENT":
        configured_controls += 1

    if dmarc["assessment"] in ["SECURE", "ACCEPTABLE"]:
        configured_controls += 1

    if mta["assessment"] in ["SECURE", "ACCEPTABLE"]:
        configured_controls += 1

    text = []

    #---------------------------------------------------------------------------
    # Introduction (first paragraph)
    #---------------------------------------------------------------------------
    intro = (
        f"An email security review was performed against the {domain} "
        "domain to assess the implementation and effectiveness of "
        "industry-standard email authentication and transport security "
        "controls."
    )

    text.append(intro)

    #---------------------------------------------------------------------------
    # Positive Controls (second paragraph)
    #---------------------------------------------------------------------------   
    
    # SPF, DKIM and DMARC controls were identified during the assessment
    if authentication_present:

        positive = (
            "SPF, DKIM and DMARC controls were identified during "
            "the assessment. "
        )

        # SPF, DKIM and DMARC controls were identified and validated
        if authentication_working:

            positive += (
                "Successful validation of these controls was observed "
                "in the supplied email sample, providing assurance "
                "that they were functioning as intended. "
            )

            # Authentication controls broadly align with recognised industry 
            # practices
            if authentication_strong:

                positive += (
                    "Collectively, these controls align with recognised "
                    "industry practices and significantly reduce exposure "
                    "to domain spoofing, impersonation attacks and "
                    "fraudulent email activity."
                )

        # SPF, DKIM and DMARC controls were identified, but validation was 
        # unsuccessful
        elif authentication_failed:

            positive += (
                "Validation of one or more email authentication controls "
                "was unsuccessful, indicating that the implemented "
                "controls may not be operating as intended and reducing "
                "confidence in the effectiveness of the domain's "
                "anti-spoofing protections."
            )

            if auth_results.get("spf") == "temperror":

                positive += (
                    " Specifically, SPF evaluation resulted in a temporary "
                    "processing error, preventing successful validation of "
                    "the configured SPF policy."
                )

        # SPF, DKIM and DMARC controls were identified; however, the supplied
        # email sample did not contain sufficient authentication results for
        # validation.
        else:

            positive += (
                "Email authentication controls were identified; however, "
                "the supplied email sample did not contain sufficient "
                "authentication results to validate their operation."
            )

    # Authentication controls were missing or inadequately implemented
    else:

        positive = (
            "The assessment identified weaknesses affecting the "
            "domain's ability to verify the authenticity of email "
            "communications, increasing exposure to spoofing and "
            "impersonation attacks."
        )

    text.append(positive)

    #-----------------------------------------------------------------------
    # Remaining risk (third paragraph)
    #-----------------------------------------------------------------------
    if spoof_result and spoof_result.get("successful"):

        text.append(
            "Despite the presence of email authentication controls, "
            "testing identified that emails claiming to originate from the "
            f"{domain} domain could be successfully spoofed. This increases "
            "the risk of phishing, impersonation and business email compromise "
            "attacks and indicates that the implemented protections may not "
            "be operating effectively in practice."
        )

    if configured_controls == 0:
    
        text.append(
            "The assessment identified significant weaknesses affecting the "
            "domain's email security posture. SPF, DKIM, DMARC and MTA-STS "
            "controls were not identified, limiting the ability of receiving "
            "organisations to verify the authenticity of email communications "
            "and increasing exposure to spoofing and impersonation attacks."
        )
    

    elif mta["assessment"] == "MISSING":

        text.append(
            "The assessment also identified an opportunity to further "
            "strengthen email security. No MTA-STS policy was identified. "
            "Whilst this does not affect the effectiveness of email "
            "authentication controls, it reduces assurance that email "
            "communications are consistently protected against downgrade "
            "or interception risks during transit between mail systems."
        )

    elif mta["assessment"] == "UNKNOWN":

        text.append(
            "The assessment also identified an opportunity to further "
            "strengthen email security. An MTA-STS DNS record was identified; "
            "however, the associated policy could not be validated. "
            "Consequently, it was not possible to confirm that the control was "
            "operating as intended."
        )

    elif mta["assessment"] in ["SECURE", "ACCEPTABLE"]:

        text.append(
            "The assessment also identified effective email transport "
            "security controls through the implementation of MTA-STS. "
            "This provides additional assurance that email communications "
            "remain protected whilst in transit between mail systems."
        )

    #-----------------------------------------------------------------------
    # Conclusion (fourth paragraph)
    #-----------------------------------------------------------------------
    if (
        authentication_strong
        and authentication_working
        and mta["assessment"] in ["SECURE", "ACCEPTABLE"]
    ):

        text.append(
            "Overall, the domain demonstrated a mature email security "
            "posture. Effective authentication and transport security "
            "controls were identified and aligned with recognised industry "
            "practices, significantly reducing exposure to spoofing, "
            "impersonation and email-based threats."
        )

    elif authentication_strong and authentication_working:

        text.append(
            "Overall, the domain demonstrated a mature email security "
            "posture. Effective authentication controls were implemented "
            "and observed to be functioning correctly, significantly "
            "reducing exposure to spoofing and impersonation attacks. "
            "Addressing the remaining transport-security weakness would "
            "further improve assurance that email communications remain "
            "secure throughout delivery and strengthen resilience against "
            "email-based threats."
        )

    elif authentication_strong and authentication_failed:

        if spoof_result and spoof_result.get("successful"):

            text.append(
                "Overall, the domain demonstrated a generally mature "
                "email security posture. Authentication controls were "
                "identified; however, validation was not fully successful "
                "and a controlled spoofing assessment demonstrated that "
                "emails claiming to originate from the domain could be "
                "successfully spoofed. These observations reduce assurance "
                "that the implemented controls are operating as intended."
            )

        else:

            text.append(
                "Overall, the domain demonstrated a generally mature email "
                "security posture. Authentication controls were identified; "
                "however, one or more validation checks were unsuccessful, "
                "reducing assurance that the controls are operating as intended."
            )

    elif authentication_present:

        text.append(
            "Overall, the domain demonstrated a generally effective "
            "email security posture; however, opportunities remain to "
            "further reduce exposure to spoofing, impersonation and "
            "other email-based threats."
        )

    else:

        text.append(
            "Overall, the domain demonstrated a weak email security "
            "posture. The absence of key authentication and transport "
            "security controls increases the likelihood of email "
            "spoofing, impersonation attacks and loss of trust in "
            "email communications originating from the domain."
        )

    return "\n\n".join(text)