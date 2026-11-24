"""
Technical commentary generation.

Builds the technical commentary section of the assessment report,
including control-specific observations and supporting evidence.
"""


from email_audit.constants import (
    DMARC_MAP,
    MTA_MAP,
)

from email_audit.dns.dkim import weak_dkim_keys
from email_audit.reporting.definitions import load_definitions

TEXT = load_definitions("narratives")['commentary']
ADDITIONAL = load_definitions("narratives")["additional_checks"]
CONTROL_DEFINITIONS = load_definitions("reference")["controls"]


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
            TEXT['build_commentary']['a_review_of_spf_dkim_dmarc_and'].format(domain=domain)
        )
    text.append("")

    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    _build_summary_table(text, spf, dkim, dmarc, mta, tls_rpt)
    _build_spf_commentary(text, spf, auth_results)
    _build_dkim_commentary(text, dkim, auth_results)
    _build_dmarc_commentary(text, dmarc)
    _build_mta_sts_commentary(text, mta)
    _build_additional_commentary(text, results)
    _build_spoofing_commentary(text, spoof_result)

    return "\n".join(text)


def _build_additional_commentary(text, results):
    tls_rpt = next((result for result in results if result["control"] == "TLS-RPT"), None)
    if tls_rpt is None:
        return
    status = tls_rpt["assessment"].lower()
    text.extend([
        ADDITIONAL["tls_rpt_heading"], "",
        CONTROL_DEFINITIONS["TLS-RPT"], "",
        ADDITIONAL[f"tls_rpt_{status}"].format(
            reason=tls_rpt["breakdown"][0] if tls_rpt["breakdown"] else ""
        ),
        "",
    ])


# ---------------------------------------------------------------------------
# Controls Configuration Summary
# ---------------------------------------------------------------------------
def _build_summary_table(text, spf, dkim, dmarc, mta, tls_rpt):
    """
    Build the controls configuration summary table.
    """
    
    text.append(TEXT['_build_summary_table']['controls_configuration_summary'])
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
    if tls_rpt is not None:
        text.append(f"| TLS-RPT | {tls_rpt['assessment']} |")

    text.append("")


# ---------------------------------------------------------------------------
# SPF Commentary
# ---------------------------------------------------------------------------
def _build_spf_commentary(text, spf, auth_results):
    """
    Build the SPF technical commentary section.
    """

    text.append(TEXT['_build_spf_commentary']['sender_policy_framework_spf'])
    text.append("")

    text.append(CONTROL_DEFINITIONS["SPF"])
    text.append("")

    if spf["assessment"] == "SECURE":

        text.append(
            TEXT['_build_spf_commentary']['the_domain_implemented_spf_using_a_restrictive']
        )

    elif spf["assessment"] == "ACCEPTABLE":

        text.append(
            TEXT['_build_spf_commentary']['the_domain_implemented_spf_and_identified_authorised']
        )

    elif spf["assessment"] == "INSECURE":

        text.append(
            TEXT['_build_spf_commentary']['the_spf_record_utilised_the_permissive_all']
        )

    elif spf["assessment"] == "MISSING":

        text.append(TEXT['_build_spf_commentary']['no_spf_record_was_identified_for_the'])
        text.append("")
        text.append(
            TEXT['_build_spf_commentary']['as_a_result_receiving_mail_systems_may']
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
                TEXT['_build_spf_commentary']['the_following_authorised_sending_services_were_identified']
            )
            text.append("")

            for provider in includes:
                text.append(f"- {provider}")

        if ips:

            text.append("")
            text.append(
                TEXT['_build_spf_commentary']['the_following_authorised_ip_addresses_were_identified']
            )
            text.append("")

            for ip in ips:
                text.append(f"- {ip}")

        text.append("")

    if auth_results:

        spf_result = auth_results.get("spf")

        if spf_result == "temperror":

            text.append(
                TEXT['_build_spf_commentary']['spf_temperror_observed']
            )

            text.append("")

            text.append(
                TEXT['_build_spf_commentary']['this_suggests_that_receiving_mail_systems_were']
            )

            text.append("")

        elif spf_result == "fail":

            text.append(
                TEXT['_build_spf_commentary']['spf_failure_observed']
            )

            text.append("")

            text.append(
                TEXT['_build_spf_commentary']['this_suggests_that_the_observed_email_message']
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

    text.append(TEXT['_build_dkim_commentary']['domainkeys_identified_mail_dkim'])
    text.append("")

    text.append(CONTROL_DEFINITIONS["DKIM"])
    text.append("")

    if dkim["assessment"] == "PRESENT":

        if auth_results and auth_results.get("dkim") == "pass":

            text.append(
                TEXT['_build_dkim_commentary']['dkim_pass_observed']
            )
            text.append("")

            text.append(
                TEXT['_build_dkim_commentary']['this_demonstrates_that_outbound_email_messages_were']
            )

        else:

            text.append(
                TEXT['_build_dkim_commentary']['dkim_key_discovered']
            )

    elif dkim["assessment"] == "UNKNOWN":

        text.append(
            TEXT['_build_dkim_commentary']['dkim_support_could_not_be_confirmed_through']
        )
        text.append("")

        text.append(
            TEXT['_build_dkim_commentary']['as_a_result_assurance_regarding_the_authenticity']
        )

    for key in weak_dkim_keys(dkim):
        text.extend([
            "",
            ADDITIONAL["weak_dkim"].format(selector=key["selector"], bits=key["key_bits"]),
        ])
    text.append("")


# ---------------------------------------------------------------------------
# DMARC Commentary
# ---------------------------------------------------------------------------
def _build_dmarc_commentary(text, dmarc):
    """
    Build the DMARC technical commentary section.
    """

    text.append(
        TEXT['_build_dmarc_commentary']['domain_based_message_authentication_reporting_and_conformance']
    )
    text.append("")

    text.append(CONTROL_DEFINITIONS["DMARC"])
    text.append("")

    tags = dmarc.get("tags", {})

    if dmarc["assessment"] == "SECURE":

        text.append(TEXT['_build_dmarc_commentary']['the_dmarc_configuration_was_observed_to'])
        text.append("")
        text.append(TEXT['_build_dmarc_commentary']['reject_messages_that_fail_authentication_checks'])

    elif dmarc["assessment"] == "ACCEPTABLE":

        text.append(TEXT['_build_dmarc_commentary']['the_dmarc_configuration_was_observed_to'])
        text.append("")

        text.append(
            TEXT['_build_dmarc_commentary']['treat_messages_that_fail_authentication_checks_as']
        )

    elif dmarc["assessment"] == "INSECURE":

        text.append(TEXT['_build_dmarc_commentary']['the_dmarc_configuration_was_observed_to'])
        text.append("")
        text.append(
            TEXT['_build_dmarc_commentary']['monitor_authentication_failures_without_enforcing_remediation_actions']
        )

    elif dmarc["assessment"] == "MISSING":

        text.append(TEXT['_build_dmarc_commentary']['no_dmarc_policy_was_identified_for_the'])
        text.append("")

        text.append(
            TEXT['_build_dmarc_commentary']['as_a_result_receiving_organisations_are_not']
        )

    if dmarc["assessment"] != "MISSING":

        if "pct" in tags:
            text.append(
                TEXT['_build_dmarc_commentary']['apply_the_policy_to_value_1_of'].format(value_1=tags['pct'])
            )

        if "adkim" in tags:
            text.append(
                TEXT['_build_dmarc_commentary']['use_value_1_dkim_alignment'].format(value_1='strict' if tags['adkim'] == 's' else 'relaxed')
            )

        if "aspf" in tags:
            text.append(
                TEXT['_build_dmarc_commentary']['use_value_1_spf_alignment'].format(value_1='strict' if tags['aspf'] == 's' else 'relaxed')
            )

        if "rua" in tags:

            text.append("")
            text.append(
                TEXT['_build_dmarc_commentary']['dmarc_aggregate_reports_were_configured_to_be']
            )
            text.append("")

            for address in tags["rua"].split(","):
                address = address.strip().replace("mailto:", "")
                text.append(f"- {address.strip()}")

        if dmarc["assessment"] == "SECURE":

            text.append("")
            text.append(
                TEXT['_build_dmarc_commentary']['this_configuration_helps_reduce_the_risk_of']
            )
            text.append("")

        elif dmarc["assessment"] == "ACCEPTABLE":

            text.append("")
            text.append(
                TEXT['_build_dmarc_commentary']['whilst_less_restrictive_than_a_reject_policy']
            )
            text.append("")

        elif dmarc["assessment"] == "INSECURE":

            text.append(
                TEXT['_build_dmarc_commentary']['although_this_configuration_provides_visibility_through_reporting']
            )
            text.append("")


# ---------------------------------------------------------------------------
# MTA-STS Commentary
# ---------------------------------------------------------------------------
def _build_mta_sts_commentary(text, mta):
    """
    Build the MTA-STS technical commentary section.
    """

    text.append(TEXT['_build_mta_sts_commentary']['mail_transfer_agent_strict_transport_security_mta'])
    text.append("")

    text.append(CONTROL_DEFINITIONS["MTA-STS"])
    text.append("")

    mta_policy = mta.get("policy", {})

    if mta["assessment"] == "SECURE":

        text.append(TEXT['_build_mta_sts_commentary']['the_mta_sts_configuration_was_observed_to'])
        text.append("")

        text.append(TEXT['_build_mta_sts_commentary']['operate_in_enforcement_mode'])

        if mta_policy["max_age"]:
            text.append(
                TEXT['_build_mta_sts_commentary']['cache_policy_information_for_value_1_seconds'].format(value_1=mta_policy['max_age'])
            )

        if mta_policy["mx"]:
            text.append("")
            text.append(
                TEXT['_build_mta_sts_commentary']['the_following_authorised_mail_servers_were_identified']
            )

            for mx in mta_policy["mx"]:
                text.append(f"- {mx}")

        text.append("")

        text.append(
            TEXT['_build_mta_sts_commentary']['this_configuration_helps_reduce_the_risk_of']
        )

    elif mta["assessment"] == "ACCEPTABLE":

        text.append(TEXT['_build_mta_sts_commentary']['the_mta_sts_configuration_was_observed_to'])
        text.append("")

        text.append(TEXT['_build_mta_sts_commentary']['operate_in_testing_mode'])

        if mta_policy["max_age"]:
            text.append(
                TEXT['_build_mta_sts_commentary']['cache_policy_information_for_value_1_seconds'].format(value_1=mta_policy['max_age'])
            )

        if mta_policy["mx"]:
            text.append("")
            text.append(
                TEXT['_build_mta_sts_commentary']['the_following_authorised_mail_servers_were_identified']
            )

            for mx in mta_policy["mx"]:
                text.append(f"- {mx}")

        text.append("")
        text.append(
            TEXT['_build_mta_sts_commentary']['although_not_fully_enforced_this_demonstrates_an']
        )

    elif mta["assessment"] == "INSECURE":

        text.append(TEXT['_build_mta_sts_commentary']['the_mta_sts_configuration_was_observed_to'])
        text.append("")
        text.append(TEXT['_build_mta_sts_commentary']['operate_in_a_non_enforcing_mode'])
        text.append("")
        text.append(
            TEXT['_build_mta_sts_commentary']['as_a_result_email_delivery_may_continue']
        )

    elif mta["assessment"] == "UNKNOWN":

        text.append(
            TEXT['_build_mta_sts_commentary']['an_mta_sts_dns_record_was_also']
        )

    elif mta["assessment"] == "MISSING":

        text.append(TEXT['_build_mta_sts_commentary']['no_mta_sts_policy_was_identified_for'])
        text.append("")
        text.append(
            TEXT['_build_mta_sts_commentary']['as_a_result_email_delivery_may_rely']
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

    text.append(TEXT['_build_spoofing_commentary']['controlled_spoofing_assessment'])
    text.append("")

    if spoof_result.get("successful"):

        text.append(
            TEXT['_build_spoofing_commentary']['a_controlled_spoofing_assessment_identified_that_an']
        )

        text.append("")

        text.append(
            TEXT['_build_spoofing_commentary']['although_email_authentication_controls_were_present_testing']
        )

    else:

        text.append(
            TEXT['_build_spoofing_commentary']['testing_did_not_identify_evidence_that_a']
        )

    text.append("")