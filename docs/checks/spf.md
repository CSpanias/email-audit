# SPF check

Sender Policy Framework (SPF) lets a domain publish which sending IP addresses
may use an SMTP identity. A receiver evaluates the record against the
connecting IP; SPF does not sign a message or verify its visible `From:`
header by itself.

## What Email Audit checks

The tool queries the target domain's TXT records and selects
an SPF record containing `v=spf1`. It displays recognised `include`, `ip4`,
`ip6` and `all` mechanisms and classifies the first `all` mechanism: `-all`
as secure, `~all` as acceptable and `+all` or `all` as insecure. A failed
lookup is inconclusive; a genuinely absent record is marked missing.

```text
v=spf1 ip4:192.0.2.10 include:mail.example.net -all
```

The `ip4` term identifies an address, while `include` delegates a matching
decision to another domain's SPF policy. `-all` yields SPF fail when earlier
mechanisms do not match; the recipient decides how to handle the result.
`~all` yields softfail; `+all` matches every sender. An unqualified `all`
has the same effect as `+all`. Mechanisms after the first `all` are ignored.

| Value | Behaviour | Use case |
|---|---|---|
| `-all` | SPF fail for unauthorised senders | Domains with a fully identified sending infrastructure |
| `~all` | SPF softfail for unauthorised senders | Common when sending sources are not yet fully known |
| `+all` | SPF pass for all senders | Testing, backwards compatibility, or (more commonly) misconfiguration |

SPF returns an authentication result; recipients decide whether to reject or
otherwise handle a message.

## Limitations

This is a simple record review, not a complete SPF evaluator. It does not
resolve all mechanisms, calculate the DNS lookup limit, detect multiple SPF
records, or establish that a specific sender will pass. Check the full policy
independently and retry inconclusive DNS lookups. A sample's reported SPF result
reflects that message's receiving system, not a new verification.

## References

- [RFC 7208: Sender Policy Framework](https://datatracker.ietf.org/doc/html/rfc7208)
- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
