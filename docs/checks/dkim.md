# DKIM check

DomainKeys Identified Mail (DKIM) signs selected message headers and body
content using a private key. A receiving system uses a public key in DNS to
verify the signature. A signature identifies its signing domain with `d=`
and selects a key with `s=`.

## What Email Audit checks

The tool queries each selector in a small list of common selectors at
`<selector>._domainkey.<target-domain>`. With an email sample, it also queries
the selector extracted from the sample against the target domain. A record
containing `v=DKIM1` is marked present; if no key can be confirmed, the
assessment is unknown.

```text
selector1._domainkey.example.com TXT "v=DKIM1; k=rsa; p=<public-key>"
```

If available, the sample's reported `dkim` authentication result is shown as
additional evidence. A published key alone does not demonstrate that
messages are signed or that a signature passes validation.

For a discovered RSA key, the public key is decoded and its modulus length is
measured. A key below 2048 bits produces `weak-dkim-rsa-key`, mapped to
SureFormat `SC-2187`. A 2048-bit or larger key does not produce that finding.
Missing, revoked, malformed or non-RSA keys do not produce a weak RSA finding;
their key-length assessment is inconclusive or not applicable.

## Limitations

Selectors can have arbitrary names, and discovery is not exhaustive. The
primary DKIM assessment uses the first non-empty common selector response,
or the sample selector when supplied. Weak RSA keys found in the other common
selectors are also reported. The sample selector is looked up against the
target domain, which may differ from the signature's `d=` domain. This is
not a complete inventory of signing keys. Signature
validity and DMARC alignment are not independently verified. An unknown
result is not proof that DKIM is absent.

## References

- [RFC 6376: DKIM signatures](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 8301: DKIM cryptographic requirements](https://datatracker.ietf.org/doc/html/rfc8301)
- [Email Security Explained](https://mollysec.com/posts/email-security-explained/)
