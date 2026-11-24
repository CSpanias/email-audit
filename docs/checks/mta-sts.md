# MTA-STS check

Mail Transfer Agent Strict Transport Security (MTA-STS) helps compatible
sending mail servers protect SMTP delivery to a domain against downgrade and
interception. A DNS record advertises a policy identifier; the policy itself
is obtained over HTTPS.

## What Email Audit checks

The tool queries `_mta-sts.<domain>` and fetches
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. It parses `version`,
`mode`, `mx` and `max_age`. It checks the DNS version and identifier, policy
version, mode, cache duration and required mail-server patterns before
classifying `enforce` as secure, `testing` as acceptable and `none` as insecure.
Multiple records or an unavailable or invalid policy are inconclusive.
Testing and non-enforcing modes are included in findings and recommendations.

For example, the DNS record can contain:

```text
v=STSv1; id=20261124
```

| DNS field | Meaning |
|---|---|
| `v=STSv1` | Identifies the MTA-STS version. |
| `id=` | Identifies a policy revision so senders can detect changes. |

The HTTPS policy can contain:

```text
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 86400
```

| Policy field | Meaning |
|---|---|
| `version` | MTA-STS policy version. |
| `mode` | Requested enforcement mode. |
| `mx` | Authorised receiving mail server pattern. |
| `max_age` | Policy cache duration in seconds. |

| Mode | Behaviour | Use case |
|---|---|---|
| `none` | Policy published but not enforced | Initial deployment |
| `testing` | Monitor failures without enforcing requirements | Validation and monitoring |
| `enforce` | Require TLS and trusted `MX` hosts for delivery | Production deployment |

TLS-RPT can provide failure reports when a reporting policy is configured.

## Limitations

This check is not a full MTA-STS or TLS validator. It does not match the
domain's live MX records against the policy, verify SMTP certificates,
or demonstrate that other senders enforce the policy. DNS and HTTPS errors
can prevent reliable confirmation.

## References

- [RFC 8461: SMTP MTA Strict Transport Security](https://datatracker.ietf.org/doc/html/rfc8461)
- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
