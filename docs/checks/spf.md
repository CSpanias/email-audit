# SPF check

Sender Policy Framework (SPF) lets a domain publish which sending IP addresses
may use an SMTP identity. A receiver evaluates the record against the
connecting IP; SPF does not sign a message or verify its visible `From:`
header by itself.

## What Email Audit checks

The tool queries the target domain's TXT records with `dig +short` and selects
an SPF record containing `v=spf1`. It displays recognised `include`, `ip4`,
`ip6` and `all` mechanisms and classifies a literal `-all` as secure, `~all`
as acceptable and `+all` as insecure. No record is marked missing.

```text
v=spf1 ip4:192.0.2.10 include:mail.example.net -all
```

The `ip4` term identifies an address, while `include` delegates a matching
decision to another domain's SPF policy. `-all` yields SPF fail when earlier
mechanisms do not match; the recipient decides how to handle the result.
`~all` yields softfail; `+all` matches every sender.

## Limitations

This is a simple record review, not a complete SPF evaluator. It does not
resolve all mechanisms, calculate the DNS lookup limit, detect multiple SPF
records, or establish that a specific sender will pass. Confirm DNS errors
and check the full policy independently. A sample's reported SPF result
reflects that message's receiving system, not a new verification.

## References

- [RFC 7208: Sender Policy Framework](https://datatracker.ietf.org/doc/html/rfc7208)
- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
