# Email-Audit

A Python-based tool designed to make email security reviews more efficient.

Developed as an educational tool to accompany [Email Security Explained: SPF, DKIM, DMARC, and MTA-STS](https://mollysec.com/posts/email-security-explained/). 

It analyses common email security mechanisms and provides a structured assessment consisting of:

```text
Raw Record → Breakdown → Security Impact → Assessment
```

## Installation

### [UV](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer) (Method 1 - Recommended)

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install email-audit via UV
uv tool install git+https://github.com/CSpanias/email-audit

# Verify installation
email-audit -h

# Update
uv tool upgrade email-audit
```

### Clone Locally (Method 2):

> **Note**: Python 3 must be installed and available in your `PATH`.

```bash
# Clone the repository
git clone https://github.com/CSpanias/email-audit /opt/email-audit

# Make the script executable
chmod +x /opt/email-audit/email_audit.py

# Create a symbolic link
sudo ln -s /opt/email-audit/email_audit.py /usr/local/bin/email-audit

# Verify installation
email-audit -h
```

## Features

The tool follows the same assessment methodology typically used during an email security review:

### 1. DNS analysis

* SPF discovery and assessment
* DMARC discovery and policy analysis
* DKIM detection using common selectors
* MTA-STS detection and policy analysis
* *Security posture scoring* (experimental)

### 2. Email analysis

* Parse `.eml` and `.msg` files
* Extract SPF, DKIM, and DMARC authentication results
* Extract DKIM signing domain and selector

### 3. Practical validation

* Optional spoofing tests using `swaks`
* Local SMTP relay support via Postfix

## Usage

```bash
# DNS Review
email-audit <domain>

# Email Header Analysis
email-audit <domain> --email <email_file>

# Spoofing Test
sudo service postfix start
email-audit <domain> --spoof <recipient>
```

## Example Output

```bash
$ email-audit <domain> --email <domain>.eml --spoof mollysec@lab.com

[*] Retrieving DNS records and analysing email controls for the <domain> domain...
```

```text
=== SPF ===

Raw Record:
v=spf1 a:mail.<domain> a:mail2.<domain> a:mail4.<domain> a:em8847.<domain> a:mail03.<domain> a:mail04.<domain> include:theaccessgroupspf.smtp.com include:mail.zendesk.com include:spf.protection.outlook.com -all

Breakdown:
  - include:theaccessgroupspf.smtp.com → Authorised third-party provider
  - include:mail.zendesk.com → Authorised third-party provider
  - include:spf.protection.outlook.com → Authorised third-party provider
  - -all → SPF enforcement policy

Security Impact:
  Unauthorised sending mail servers should be rejected.

Assessment:
  SECURE
```

```text
=== DKIM ===

Raw Record:
selector2-ventrica-co-uk._domainkey.ventricacouk.onmicrosoft.com.
"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+6zgttsPLlvQlDAFtJ9Er7u2YNf8qMVaAdxSJnm7JpXcizQ+ZiN2fB9W0gDlNn2rLzXtm+g2GKp2pQVdypBdNarNvePsiDDygD0Aazhns7J5fXarRYQTOKbMgrZBwbel68efXJmJJMxcsIiK/SgCPP3j4I4nM8fBr9u+wfRrU1QzUztSqoRIjGmdaghBP+yH" "Oga3OG+jvB/PCh8KeT5uOHtlO0M1Lt8tmLWpanudM6w4ZT85rMrC1Feso6qXsEJB7sFagAz6WNzQ2gIb9cHEsrmyaOqU6KbiKH+1VFZch1yJWkRRZBeYE2hP/Jwmv/hjFjww2GcBB1be9nvXQd9gQIDAQAB;"

Breakdown:
  - Common selector discovered: selector2
  - Public key present in DNS

Security Impact:
  The domain supports DKIM signature validation and DKIM was observed to be functioning correctly within the supplied email sample.

Assessment:
  PRESENT
```

```text
=== DMARC ===

Raw Record:
v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@<domain>; ruf=mailto:dmarc@<domain>; rf=afrf; pct=100; ri=86400

Breakdown:
  - p=quarantine → Failed messages should be treated as suspicious
  - pct=100 → Policy applies to 100% of messages
  - rua=mailto:dmarc@<domain> → Aggregate DMARC reports destination
  - sp=quarantine → Policy applied to subdomains

Security Impact:
  Messages failing authentication should normally be treated as suspicious.

Assessment:
  ACCEPTABLE
```

```text
=== MTA-STS ===

Breakdown:
  - No MTA-STS record present

Security Impact:
  SMTP delivery may rely solely on opportunistic TLS.

Assessment:
  MISSING
```

```text
=== EMAIL SECURITY SUMMARY ===

SPF         SECURE
DKIM        PRESENT
DMARC       ACCEPTABLE
MTA-STS     MISSING

Overall Security Posture: MODERATE (6/10)
```

```text
=== OBSERVED AUTHENTICATION RESULTS ===

SPF:   PASS
DKIM:  PASS
DMARC: PASS
```

```text
=== SPOOFING TEST ===

Test Details:
Sender:     ceo@<domain>.com
Recipient:  mollysec@lab.com
Subject:    Subject: Controlled Spoofing Assessment

Assessment:
MESSAGE SUBMITTED

Security Impact:
  The spoofed email was accepted by the local SMTP relay and submitted for delivery. 
  Recipient-side validation is required to determine whether SPF, DKIM, and DMARC protections were
  successfully enforced.
```

```text
[+] Assessment complete
[+] Findings Exported : 2
[+] XML Output        : <domain>.xml
[+] Markdown Output   : <domain>.md
```

The Markdown file will include the Executive Summary, Technical Commentary, and Solution sections.

```text
## Executive Summary

An email security review was performed against the <domain> domain to assess the implementation of industry-standard email authentication and transport security controls.

The assessment identified the implementation of SPF, DKIM and DMARC controls designed to reduce the risk of domain spoofing and improve confidence in the authenticity of email communications.

Successful SPF, DKIM and DMARC validation was observed within the supplied email sample, indicating that the authentication controls were functioning as intended.

No MTA-STS policy was identified. This may reduce assurance that email communications are consistently delivered using trusted encrypted channels between mail systems.

Overall, the domain demonstrated a generally mature email security posture with effective email authentication controls, although opportunities were identified to further strengthen email transport security.
```

```text
## Technical Commentary

A review of SPF, DKIM, DMARC and MTA-STS controls was performed against the <domain> domain to assess the implementation of email authentication and transport security controls.

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

- mailto:dmarc@<domain>

Whilst less restrictive than a reject policy, this configuration still provides meaningful protection against spoofing and may help reduce the likelihood of fraudulent messages reaching end users.

### Mail Transfer Agent Strict Transport Security (MTA-STS)

Mail Transfer Agent Strict Transport Security (MTA-STS) is an email transport security mechanism that helps ensure SMTP communications are delivered over trusted TLS-encrypted channels and reduces the risk of downgrade attacks.

No MTA-STS policy was identified for the domain.

As a result, email delivery may rely solely on opportunistic TLS, reducing assurance that messages are delivered over trusted encrypted channels and increasing exposure to SMTP downgrade attacks.
```

```text
## Recommendations

The identified weaknesses should be addressed to further strengthen the domain's email security posture:

- Publish MTA-STS to strengthen SMTP transport security and reduce the risk of downgrade attacks.

Following implementation, the effectiveness of the controls should be validated through periodic reviews and testing to ensure they continue to operate as intended.

### References

- [https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection](https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection)
- [https://datatracker.ietf.org/doc/html/rfc8461](https://datatracker.ietf.org/doc/html/rfc8461)
- [https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing](https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing)
```

## Requirements

### Core

* Python 3
* dig

### Optional

* [msgconvert](https://github.com/mvz/email-outlook-message-perl) (`.msg` support) → `sudo apt install libemail-outlook-message-perl` 
* [swaks](https://www.kali.org/tools/swaks/) (spoofing tests)
* postfix (local SMTP relay)

## Roadmap

* Implement DKIM key length check
* TLS-RPT analysis
* Enhanced scoring based on observed authentication results
* Accept multiple domains and files