# Email-Audit

A Python-based tool designed to make email security reviews more efficient.

Developed as an educational tool to accompany [Email Security Explained: SPF, DKIM, DMARC, and MTA-STS](https://mollysec.com/posts/email-security-explained/). 

For installation, workflow details and output formats, see the
[documentation](https://cspanias.github.io/email-audit/).

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

### Clone Locally (Method 2)

Python 3.10 or later and pip must be installed.

```bash
# Clone the repository
git clone https://github.com/CSpanias/email-audit /opt/email-audit

cd /opt/email-audit
python -m pip install .

# Verify installation
email-audit -h
```

## Features

The tool follows the same assessment methodology typically used during an email security review:

### 1. DNS analysis

* SPF discovery and assessment
* DMARC discovery and policy analysis
* DKIM detection using common selectors
* DKIM RSA key length assessment
* MTA-STS detection and policy analysis
* TLS-RPT reporting policy assessment
* Interactive progress for DNS checks

### 2. Email analysis

* Parse `.eml` and `.msg` files
* Extract SPF, DKIM, and DMARC authentication results
* Extract DKIM signing domain and selector

### 3. Practical validation

* Optional spoofing tests using `swaks`
* Local SMTP relay support via Postfix

### 4. Reporting

* Self-contained HTML report generation
* JSON findings export or optional SureFormat XML
* Rich console evidence tables

## Usage

```bash
# DNS Review
email-audit <domain>

# Email Header Analysis
email-audit <domain> --email <email_file>

# Spoofing Test
sudo service postfix start
email-audit <domain> --spoof <recipient>

# Export SureFormat XML instead of JSON
email-audit <domain> --csacyber
```

## Example Output

The checks are displayed in sections with the raw record and its breakdown:

```text
[SPF]

┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field   ┃ Details                        ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Record  │ v=spf1 -all                    │
│ Details │ -all → SPF enforcement policy  │
└─────────┴────────────────────────────────┘
```

Inconclusive checks include an explanatory note. If an email sample is
provided, configuration and authentication evidence tables are also shown.

The HTML report includes the executive summary, technical commentary and
recommendations, with buttons to copy narrative sections as
Markdown. Reports and findings are written to an `email-audit` directory
under the current directory, with a matching timestamp in each filename.
The following are illustrative excerpts:

```text
## Executive Summary

An email security review was performed for <domain> to assess how well the organisation protects its email communications and recipients.

Measures to help recipients verify the origin of email were identified. The supplied email passed the checks recorded for that message, but this does not demonstrate that fraudulent messages will always be blocked.

The review also identified areas where email security could be strengthened. Additional protection for email in transit was not identified, increasing the possibility that messages could be intercepted or altered.

Overall, further action is needed to improve confidence in the security of email communications.
```

```text
## Technical Commentary

A review of SPF, DKIM, DMARC and MTA-STS controls was performed against the <domain> domain to assess the implementation of email authentication and transport security controls.

### Controls Overview

| Control | Configuration |
|---------|---------------|
| SPF | Hard Fail (-all) |
| DKIM | Selector Present |
| DMARC | Quarantine |
| MTA-STS | Not Present |

### Sender Policy Framework (SPF)

Sender Policy Framework (SPF) is an email authentication mechanism that enables domain owners to explicitly identify the systems authorised to send email on behalf of the domain.

The domain utilised a restrictive SPF configuration with a hard-fail enforcement policy, helping receiving mail systems identify authorised sending infrastructure and reject unauthorised sources.

The following authorised sending services were identified:
- theaccessgroupspf.smtp.com
- mail.zendesk.com
- spf.protection.outlook.com

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

- dmarc@<domain>

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

* Python 3.10 or later
* dig

### Optional

* [msgconvert](https://github.com/mvz/email-outlook-message-perl) (`.msg` support) → `sudo apt install libemail-outlook-message-perl` 
* [swaks](https://www.kali.org/tools/swaks/) (spoofing tests)
* postfix (local SMTP relay)

## Development

```bash
python -m pip install -e ".[docs]"
python -m unittest discover -s tests
python -m mkdocs build --strict
```

## Roadmap

* Accept multiple domains and files