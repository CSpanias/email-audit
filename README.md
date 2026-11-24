# Email-Audit

Email Audit is a command-line tool for authorised email security assessments.
It accompanies [Email Security Explained: SPF, DKIM, DMARC, and MTA-STS](https://mollysec.com/posts/email-security-explained/).

## Features

* Review SPF, DKIM, DMARC, MTA-STS and TLS-RPT configuration.
* Analyse email authentication results and optionally test spoofing.
* Generate an HTML report and JSON findings.

## Quick start

Install with [uv](https://docs.astral.sh/uv/getting-started/installation/):

```bash
uv tool install git+https://github.com/CSpanias/email-audit
email-audit -D example.com
```

Only assess domains and send test messages when authorised to do so.

See the [documentation](https://cspanias.github.io/email-audit/) for
installation options, requirements, usage, development and background on
the checks.