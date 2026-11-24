# MTA-STS check

Mail Transfer Agent Strict Transport Security (MTA-STS) helps compatible
sending mail servers protect SMTP delivery to a domain against downgrade and
interception. A DNS record advertises a policy identifier; the policy itself
is obtained over HTTPS.

## What Email Audit checks

The tool queries `_mta-sts.<domain>` and fetches
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. It parses `version`,
`mode`, `mx` and `max_age`. With a DNS record, the tool classifies `enforce`
as secure, `testing` as acceptable and `none` as insecure; an unavailable or
unrecognised mode is unknown.

```text
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 86400
```

In enforcement mode, participating sending servers require a valid TLS
connection to an authorised MX host. `max_age` controls how long a policy is
cached. Testing mode does not enforce delivery requirements.

## Limitations

This check is not a full MTA-STS or TLS validator. It does not validate all
policy fields, match MX records against the policy, verify SMTP certificates,
or demonstrate that other senders enforce the policy. DNS and HTTPS errors
can prevent reliable confirmation.

## References

- [RFC 8461: SMTP MTA Strict Transport Security](https://datatracker.ietf.org/doc/html/rfc8461)
- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
