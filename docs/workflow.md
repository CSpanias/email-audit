# Assessment workflow

Only assess domains and send test messages when authorised to do so.

## DNS review

```bash
email-audit example.com
```

The tool queries SPF, common DKIM selectors, DMARC, MTA-STS and TLS-RPT, and
retrieves the MTA-STS policy over HTTPS. An interactive terminal shows progress
through these five checks; redirected output does not include a progress bar.
Failure to discover a common DKIM selector does not establish that DKIM is
absent.

## Email sample

```bash
email-audit example.com --email sample.eml
```

An `.eml` or `.msg` sample adds authentication evidence. If a DKIM selector
is present in the sample, it is queried for the target domain.
Authentication results are taken from the supplied message headers, not
independently verified.

## Controlled spoofing

```bash
email-audit example.com --spoof recipient@example.com
```

The message uses `ceo@<domain>` as its sender and is submitted through the
local SMTP relay. Submission is not proof of delivery: confirm delivery at the
recipient when prompted.

## Output

Files are written in the current directory and existing files with the same
names are overwritten:

- `<domain>.html`: a self-contained report with control assessments, executive
  summary, technical commentary, recommendations and findings.
- `<domain>.json`: findings, by default.
- `<domain>.xml`: SureFormat findings when `--csacyber` is supplied instead
  of the JSON export. Unmapped findings are reported as warnings.

Console evidence tables are displayed when an email sample is supplied.

## Reporting definitions

Finding descriptions and SureFormat IDs are maintained in
`email_audit/data/findings.yaml`. Report narratives, control definitions and
references are in `narratives.yaml` and `reference.yaml` in the same directory.
The Python code determines which definitions apply. These packaged files are
intended for maintainers; assessment rules remain in Python.
