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
* JSON findings export
* Rich console evidence tables

## Usage

```bash
# DNS Review
email-audit <domain>

# Email Header Analysis
email-audit <domain> --email <email_file>

# Spoofing Test
email-audit <domain> --spoof <recipient>

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