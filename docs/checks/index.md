# Checks

Email Audit runs the following DNS-based checks for the supplied domain:

| Check | Question | Evidence |
|---|---|---|
| [SPF](spf.md) | Which infrastructure may send for an identity? | Domain TXT record |
| [DKIM](dkim.md) | Can a signing key be discovered and is its RSA key long enough? | Selector TXT record |
| [DMARC](dmarc.md) | What policy is published for authentication failures? | `_dmarc` TXT record |
| [MTA-STS](mta-sts.md) | Is a mail transport policy advertised? | DNS TXT record and HTTPS policy |
| [TLS-RPT](tls-rpt.md) | Is a reporting policy available for SMTP TLS? | `_smtp._tls` TXT record |

An optional email sample supplies reported authentication results, while an
optional controlled spoofing test provides recipient-specific delivery
evidence. The checks are not complete protocol validators. Check the individual
pages for limitations.

New to DNS? Start with [DNS and email basics](../knowledge-base/dns-and-email.md).
