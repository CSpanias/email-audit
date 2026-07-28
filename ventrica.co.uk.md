## Executive Summary

An email security review was performed against the ventrica.co.uk domain to assess the implementation of industry-standard email authentication and transport security controls.

The assessment identified the implementation of SPF, DKIM and DMARC controls designed to reduce the risk of domain spoofing and improve confidence in the authenticity of email communications.

Successful SPF, DKIM and DMARC validation was observed within the supplied email sample, indicating that the authentication controls were functioning as intended.

No MTA-STS policy was identified. This may reduce assurance that email communications are consistently delivered using trusted encrypted channels between mail systems.

Overall, the domain demonstrated a generally mature email security posture with effective email authentication controls, although opportunities were identified to further strengthen email transport security.

## Technical Commentary

A review of SPF, DKIM, DMARC and MTA-STS controls was performed against the ventrica.co.uk domain to assess the implementation of email authentication and transport security controls.

### Controls Overview

| Control | Configuration | Status |
|---------|---------------|--------|
| SPF | Hard Fail (-all) | Fully Implemented |
| DKIM | Selector Present | Fully Implemented |
| DMARC | Quarantine | Partially Implemented |
| MTA-STS | Not Present | Not Implemented |

### Sender Policy Framework (SPF)

Sender Policy Framework (SPF) is an email authentication mechanism that enables domain owners to explicitly identify the systems authorised to send email on behalf of the domain.

The domain utilised a restrictive SPF configuration with a hard-fail enforcement policy, helping receiving mail systems identify authorised sending infrastructure and reject unauthorised sources.

The following authorised sending services were identified:
- include:theaccessgroupspf.smtp.com
- include:mail.zendesk.com
- include:spf.protection.outlook.com

This configuration helps reduce the risk of email spoofing and improves confidence in the authenticity of messages originating from the domain.

### DomainKeys Identified Mail (DKIM)

DomainKeys Identified Mail (DKIM) is an email authentication mechanism that uses cryptographic signatures to allow receiving mail systems to verify that messages were authorised by the sending domain and were not modified in transit.

DKIM support was identified through published DNS records and successful DKIM validation was observed within the supplied email sample.

This demonstrates that outbound email messages were cryptographically signed and successfully validated by receiving mail systems.

### Domain-based Message Authentication, Reporting and Conformance (DMARC)

Domain-based Message Authentication, Reporting and Conformance (DMARC) is an email authentication and policy framework that builds upon SPF and DKIM by instructing receiving organisations how to handle messages that fail authentication checks.

The DMARC configuration was observed to:

- Treat messages that fail authentication checks as suspicious.
- Apply the policy to 100% of received messages.

DMARC aggregate reports were configured to be sent to:

- mailto:dmarc@ventrica.co.uk

Whilst less restrictive than a reject policy, this configuration still provides meaningful protection against spoofing and may help reduce the likelihood of fraudulent messages reaching end users.

### Mail Transfer Agent Strict Transport Security (MTA-STS)

Mail Transfer Agent Strict Transport Security (MTA-STS) is an email transport security mechanism that helps ensure SMTP communications are delivered over trusted TLS-encrypted channels and reduces the risk of downgrade attacks.

No MTA-STS policy was identified for the domain.

As a result, email delivery may rely solely on opportunistic TLS, reducing assurance that messages are delivered over trusted encrypted channels and increasing exposure to SMTP downgrade attacks.

## Recommendations

The identified weaknesses should be addressed to further strengthen the domain's email security posture:

- Deploy MTA-STS to strengthen SMTP transport security and reduce the risk of downgrade attacks.

Following implementation, the effectiveness of the controls should be validated through periodic reviews and testing to ensure they continue to operate as intended.

### References

- [https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection](https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection)
- [https://datatracker.ietf.org/doc/html/rfc8461](https://datatracker.ietf.org/doc/html/rfc8461)
- [https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing](https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing)

