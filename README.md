# Email-Audit

A Python-based tool designed to make email configuation reviews more efficient.

Developed as an educational tool to accompany the [Email Security Explained: SPF, DKIM, DMARC, and MTA-STS](https://mollysec.com/posts/assessing-email-security/) article. 

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
* MTA-STS detection
* ~~*Security posture scoring*~~ (Pretty arbitrary for now - WIP)

### Email Analysis

* Parse `.eml` files
* Extract SPF, DKIM, and DMARC authentication results
* Extract DKIM signing domain and selector
* Validate whether DNS controls are actually being used in practice

### ~~*Spoofing Validation*~~ (Currently not implemented - WIP)

* Optional spoofing tests using `swaks`
* Local SMTP relay support via Postfix

## Usage

### DNS Review

```bash
python3 email-audit.py <domain>
```

Example:

```bash
python3 email-audit.py google.com
```

### Email Header Analysis

```bash
python3 email-audit.py <domain> --eml <email_file>
```

Example:

```bash
python3 email-audit.py hackthebox.com --eml htb-email.eml
```

### ~~*Spoofing Test*~~ (Currently not implemented - WIP)

```bash
python3 email-audit.py <domain> --spoof --to <recipient>
```

Example:

```bash
python3 email-audit.py example.com --spoof --to lab@example.net
```

## Example Output

```text
=== SPF ===

Raw Record:
v=spf1 include:_spf.google.com ~all

Breakdown:
    - include:_spf.google.com → Authorised third-party provider
    - ~all → SPF enforcement policy

Security Impact:
    Unauthorised senders may still be accepted by some recipients.

Assessment:
    ACCEPTABLE
```

```text
=== OBSERVED AUTHENTICATION RESULTS ===

SPF:   PASS
DKIM:  PASS
DMARC: PASS

DKIM Details:
    Signing Domain: hackthebox.com
    Selector: google
```

## Requirements

### Core

* Python 3
* dig

### ~~*Optional*~~ (Currently not implemented - WIP)

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

3. ~~*Practical validation*~~ (Currently not implemented - WIP)
   * Controlled spoofing tests

## Limitations

* DKIM detection is currently based on common selector enumeration.
* DNS-based DKIM detection confirms support for DKIM but does not confirm implementation.
* Full validation requires inspection of a real email (`.eml`) file.
* Spoofing tests must only be performed against authorised targets.

## Roadmap

* Improved DKIM selector discovery
* MTA-STS policy retrieval and validation
* Enhanced scoring based on observed authentication results
* Microsoft Outlook (`.msg`) support
* TLS-RPT analysis
* Exportable assessment reports in `.xml` format