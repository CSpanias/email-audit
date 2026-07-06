# Email-Audit

A Python-based tool designed to make email security reviews more efficient.

Developed as an educational tool to accompany [Email Security Explained: SPF, DKIM, DMARC, and MTA-STS](https://mollysec.com/posts/email-security-explained/). 

It analyses common email security mechanisms and provides a structured assessment consisting of:

```text
Raw Record → Breakdown → Security Impact → Assessment
```

## Installation

Recommended ([uv](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer)):

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

Clone locally:

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
* Automatically convert `.msg` files using `msgconvert`
* Extract SPF, DKIM, and DMARC authentication results
* Extract DKIM signing domain and selector
* Validate whether SPF, DKIM, and DMARC are functioning in practice

### 3. Practical validation

* Optional spoofing tests using `swaks`
* Local SMTP relay support via Postfix
* Submission outcome reporting

## Usage

### DNS Review

```bash
email-audit <domain>

email-audit kairos-sec.com
```

### Email Header Analysis

```bash
email-audit <domain> --email <email_file>

email-audit kairos-sec.com --email kairos-sec-email.eml
```

### Spoofing Test

```bash
sudo service postfix start

email-audit <domain> --spoof <recipient>

email-audit kairos-sec.com --spoof mollysec@lab.com
```

## Example Output

```bash
email-audit kairos-sec.com --email kairos-sec-email.eml --spoof mollysec@lab.com
```

```text
KAIROS-SEC.COM

=== SPF ===

Raw Record:
v=spf1 a mx include:_spf.mlsend.com ~all

Breakdown:
  - include:_spf.mlsend.com → Authorised third-party provider
  - ~all → SPF enforcement policy

Security Impact:
  Unauthorised senders may still be accepted by some recipients.

Assessment:
  ACCEPTABLE
```

```text
=== DMARC ===

Breakdown:
  - No DMARC record present

Security Impact:
  Receiving servers are not given any policy for handling authentication failures.

Assessment:
  MISSING
```

```text
=== DKIM ===

Raw Record:
"v=DKIM1;k=rsa;p=MII...QAB"

Breakdown:
  - Common selector discovered: default
  - Public key present in DNS

Security Impact:
  The domain supports DKIM signature validation. Actual implementation still requires inspection of a received email.

Assessment:
  PRESENT
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

SPF         ACCEPTABLE
DMARC       MISSING
DKIM        PRESENT
MTA-STS     MISSING

Overall Security Posture: WEAK (3/10)
```

```text
=== OBSERVED AUTHENTICATION RESULTS ===

SPF:   UNKNOWN
DKIM:  PASS
DMARC: UNKNOWN

DKIM Details:
Signing Domain: kairos-sec-com.20230601.gappssmtp.com
Selector: 20230601
```

```text
=== SPOOFING TEST ===

Test Details:
Sender:     ceo@kairos-sec.com
Recipient:  mollysec@lab.com
Subject:    Subject: Controlled Spoofing Assessment

Assessment:
MESSAGE SUBMITTED

Security Impact:
  The spoofed email was accepted by the local SMTP relay and submitted for delivery. 
  Recipient-side validation is required to determine whether SPF, DKIM, and DMARC protections were
  successfully enforced.
```

## Requirements

### Core

* Python 3
* dig

### Optional

* [msgconvert](https://github.com/mvz/email-outlook-message-perl) (`.msg` support) → `sudo apt install libemail-outlook-message-perl` 
* [swaks](https://www.kali.org/tools/swaks/) (spoofing tests)
* postfix (local SMTP relay)

## Limitations

* DNS-based DKIM detection confirms support for DKIM but does not confirm implementation.
* Full validation requires inspection of a real email (`.eml` or `.msg`) file.
* Spoofing tests (performed against authorised targets!) confirm message submission only; manual validation is required.

## Roadmap

* Enhanced scoring based on observed authentication results
* TLS-RPT analysis
* Exportable assessment reports in `.xml` format
