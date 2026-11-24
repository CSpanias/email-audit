# DNS and email basics

This primer provides the context needed to interpret the
[email security checks](../checks/index.md). For a longer introduction, see
[Email Security Explained](https://mollysec.com/posts/email-security-explained/).

## What DNS does

The Domain Name System (DNS) maps names to records. A DNS resolver asks
authoritative name servers for information about a name and caches answers
according to the record's time to live (TTL). A DNS query may return no
record, or it may fail because of a timeout or another resolution error; these
outcomes should not be treated as equivalent.

| Record | Purpose |
|---|---|
| `A` | IPv4 address for a name. |
| `AAAA` | IPv6 address for a name. |
| `CNAME` | Alias pointing to another DNS name. |
| `NS` | Authoritative name servers for a zone. |
| `MX` | Mail servers that accept mail for a domain, with a preference value. |
| `TXT` | Text data used by email authentication and other services. |

`dig` can inspect these records, for example:

```bash
dig +short example.com MX
dig +short example.com TXT
dig +short _dmarc.example.com TXT
```

Different controls use different names: SPF is normally at the domain itself;
DMARC is at `_dmarc.<domain>`; DKIM keys are at
`<selector>._domainkey.<signing-domain>`; and MTA-STS advertises a policy at
`_mta-sts.<domain>`; and TLS-RPT uses `_smtp._tls.<domain>`. A DNS answer is public configuration, not proof that
every message uses the control.

## How email is delivered

The sender's mail system uses SMTP to pass a message to the recipient's mail
system. MX records help identify the recipient domain's inbound mail servers.
The visible `From:` header identifies the author to the reader; SMTP also
uses an envelope sender, which can differ from that header. These identities
matter because SPF and DMARC do not necessarily check the same domain.

SPF checks the sending IP against the envelope sender domain (or the HELO
identity in relevant cases). DKIM verifies a signature against a public key.
DMARC requires an aligned SPF or DKIM pass relative to the visible `From:`
domain and publishes a policy for failures. MTA-STS addresses TLS transport
between mail servers rather than sender authentication. TLS-RPT specifies
where compatible senders can report transport failures.

## Evidence and limits

The `Authentication-Results` header records a receiving system's reported
results; it is not itself proof that Email Audit verified the message. Use a
trusted sample and corroborate its source. DNS configuration, authentication
results, and delivery of a controlled test each answer different questions.
None guarantees that all recipients will handle messages identically.

## References

- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
- [RFC 1034: DNS concepts](https://datatracker.ietf.org/doc/html/rfc1034)
- [RFC 5321: SMTP](https://datatracker.ietf.org/doc/html/rfc5321)
- [RFC 8601: Authentication-Results](https://datatracker.ietf.org/doc/html/rfc8601)
