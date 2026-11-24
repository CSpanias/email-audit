# DMARC check

Domain-based Message Authentication, Reporting and Conformance (DMARC) uses
SPF and DKIM results together with domain alignment. A message passes DMARC
when at least one of those checks passes with an identity aligned to the
visible `From:` domain. The published policy requests how receivers handle
failures; receivers retain their own handling decisions.

## What Email Audit checks

The tool queries TXT records at `_dmarc.<domain>`, parses tags and classifies
`p=reject` as secure, `p=quarantine` as acceptable and `p=none` as insecure
when no reduced-coverage setting is present. It also displays selected tags
when present.

```text
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

| Field | Meaning |
|---|---|
| `v=` | DMARC version. |
| `p=` | Requested policy for the domain. |
| `sp=` | Requested policy for subdomains. |
| `rua=` | Destination for aggregate reports. |
| `fo=` | Conditions for requesting failure reports. |
| `adkim=` / `aspf=` | DKIM / SPF alignment mode. |
| `pct=` | Legacy percentage for policy sampling. |
| `t=` | Policy testing flag. |

The legacy `pct` tag requested the policy for a percentage of messages.
For example, `p=reject; pct=0` could lead older receivers to quarantine
rather than reject failing messages. The current DMARC specification replaced
`pct` with `t=y`, which requests testing at one level below the published
policy. Receivers may implement these settings differently.

The tool conservatively marks `p=reject` with `pct` below 100 or `t=y` as
acceptable rather than secure, and `p=quarantine` with either setting as
insecure rather than acceptable. Invalid or duplicated coverage tags make
an enforcing policy's assessment inconclusive. `p=none` remains monitoring-only.
Multiple DMARC records, duplicate policy tags and invalid policy or alignment
values are also flagged for review rather than classified as enforced.

| Policy | Behaviour | Use case |
|---|---|---|
| `none` | Monitor only; do not enforce | Initial deployment, testing, and collecting DMARC reports |
| `quarantine` | Treat messages as suspicious (e.g. spam folder) | Gradual enforcement while reducing the risk of blocking legitimate emails |
| `reject` | Reject messages that fail DMARC | Mature email environments with well-understood sending infrastructure |

These are requests to receiving systems; they determine how to handle messages.

## Limitations

Classification considers `p`, legacy `pct` and `t`, but is not a complete DMARC evaluation.
The tool does not verify organisational-domain inheritance, alignment,
report destination authorisation, effective policy coverage, or receiver
behaviour. A sample reports a receiving system's authentication result
rather than a fresh DMARC evaluation.

## References

- [RFC 7489: DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [RFC 9989: DMARC](https://datatracker.ietf.org/doc/html/rfc9989)
- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
