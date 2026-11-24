# TLS-RPT check

SMTP TLS Reporting (TLS-RPT) tells compatible sending mail servers where to
send aggregate information about TLS delivery issues. It supports monitoring
MTA-STS, DANE and other SMTP transport failures, but does not itself enforce
TLS.

## What Email Audit checks

The tool queries TXT records at `_smtp._tls.<domain>` and joins the character
strings in each TXT record. It looks for a version-one TLS-RPT policy and
checks the version, field structure, number of policies and reporting
destinations. It accepts `mailto` and `https` destinations.

```text
v=TLSRPTv1; rua=mailto:tls-reports@example.com
```

| Field | Meaning |
|---|---|
| `v=` | TLS-RPT version. |
| `rua=` | Destination or destinations for aggregate reports. |

| Result | Finding |
|---|---|
| No version-one policy | `missing-tls-rpt` |
| Malformed policy, duplicate policies or invalid destination | `invalid-tls-rpt` |
| DNS lookup or decoding failure | Inconclusive; no missing or invalid finding |

Unrelated TXT records and other TLS-RPT versions are not treated as version-one
policies. Unknown, syntactically valid extension fields are ignored.

## Limitations

The check performs basic syntax validation; it does not contact destinations,
prove reports are being delivered or reviewed, or exhaustively validate every
URI form. A published record does not establish that the domain uses MTA-STS,
that senders support TLS-RPT, or that TLS is enforced.

## References

- [RFC 8460: SMTP TLS Reporting](https://datatracker.ietf.org/doc/html/rfc8460)
- [RFC 8461: SMTP MTA Strict Transport Security](https://datatracker.ietf.org/doc/html/rfc8461)
