# DMARC check

Domain-based Message Authentication, Reporting and Conformance (DMARC) uses
SPF and DKIM results together with domain alignment. A message passes DMARC
when at least one of those checks passes with an identity aligned to the
visible `From:` domain. The published policy requests how receivers handle
failures; receivers retain their own handling decisions.

## What Email Audit checks

The tool queries TXT records at `_dmarc.<domain>`, parses tags and classifies
`p=reject` as secure, `p=quarantine` as acceptable and `p=none` as insecure.
It also displays selected tags such as `pct`, `rua`, `sp`, `adkim` and
`aspf` when present.

```text
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

`rua` specifies an aggregate reporting destination. `sp` supplies a
subdomain policy; `adkim` and `aspf` indicate strict or relaxed alignment.
Legacy `pct` indicates a requested policy percentage.

## Limitations

Classification is based on the `p` tag, not a complete DMARC evaluation.
The tool does not verify organisational-domain inheritance, alignment,
report destination authorisation, effective policy coverage, or receiver
behaviour. A sample reports a receiving system's authentication result
rather than a fresh DMARC evaluation.

## References

- [RFC 7489: DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
