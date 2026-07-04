# Email-Audit

A Python-based tool designed to make email security reviews more efficient.

Developed as an educational tool to accompany [Email Security Explained: SPF, DKIM, DMARC, and MTA-STS](https://mollysec.com/posts/email-security-explained/). 

It analyses common email security mechanisms and provides a structured assessment consisting of:

```text
Raw Record
    ↓
Breakdown
    ↓
Security Impact
    ↓
Assessment
````

## Features

### DNS Analysis

* SPF discovery and assessment
* DMARC discovery and policy analysis
* DKIM detection using common selectors
* MTA-STS detection and policy analysis
* *Security posture scoring* (experimental - WIP)

### Email Analysis

* Parse `.eml` files
* Extract SPF, DKIM, and DMARC authentication results
* Extract DKIM signing domain and selector
* Validate whether SPF, DKIM, and DMARC are functioning in practice

### Spoofing Validation

* Optional spoofing tests using `swaks`
* Local SMTP relay support via Postfix
* Submission outcome reporting

## Usage

### DNS Review

```bash
./email-audit.py <domain>
```

Example:

```bash
./email-audit.py google.com
```

### Email Header Analysis

```bash
./email-audit.py <domain> --eml <email_file>
```

Example:

```bash
./email-audit.py hackthebox.com --eml htb-email.eml
```

### Spoofing Test

```bash
./email-audit.py <domain> --spoof <recipient>
```

Example:

```bash
./email-audit.py example.com --spoof lab@example.net
```

## Example Output

```bash
./email-audit.py kairos-sec.com --eml kairos-sec-com-test.eml --spoof testing@test.com
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
  - selector=default → DNS lookup location
  - Public key present in DNS

Security Impact:
  The domain supports DKIM signature validation.
  Actual implementation still requires inspection of a received email.

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
Recipient:  testing@test.com
Subject:    Subject: Controlled Spoofing Assessment

Assessment:
MESSAGE SUBMITTED

Security Impact:
  The spoofed email was accepted by the local SMTP relay and submitted for delivery. 
  Recipient-side validation is required to determine whether SPF, DKIM, and DMARC protections 
  were successfully enforced.
```

## Requirements

### Core

* Python 3
* dig

### Optional

* swaks (spoofing tests)
* postfix (local SMTP relay)

## Assessment Methodology

The tool follows the same process typically used during an email security review:

1. DNS analysis
   * SPF
   * DKIM
   * DMARC
   * MTA-STS

2. Email analysis
   * Authentication-Results
   * DKIM-Signature
   * SPF outcomes
   * DMARC outcomes

3. Practical validation
   * Controlled spoofing tests

## Limitations

* DKIM detection is currently based on common selector enumeration.
* DNS-based DKIM detection confirms support for DKIM but does not confirm implementation.
* Full validation requires inspection of a real email (`.eml`) file.
* Spoofing tests (performed against authorised targets!) confirm message submission only; manual validation is required.

## Roadmap

* Improved DKIM selector discovery
* Enhanced scoring based on observed authentication results
* Microsoft Outlook (`.msg`) support
* TLS-RPT analysis
* Exportable assessment reports in `.xml` format