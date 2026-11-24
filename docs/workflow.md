# Assessment workflow

Only assess domains and send test messages when authorised to do so.

## DNS review

```bash
email-audit -D example.com
```

The tool queries SPF, common DKIM selectors, DMARC, MTA-STS and TLS-RPT, and
retrieves the MTA-STS policy over HTTPS. An interactive terminal shows progress
through these five checks; redirected output does not include a progress bar.
Failure to discover a common DKIM selector does not establish that DKIM is
absent.

## Email sample

```bash
email-audit -D example.com --email sample.eml
```

An `.eml` or `.msg` sample adds authentication evidence. If a DKIM selector
is present in the sample, it is queried for the target domain.
Authentication results are taken from the supplied message headers, not
independently verified.

## Controlled spoofing

```bash
email-audit -D example.com --spoof recipient@example.com
```

The message uses `ceo@<domain>` as its sender and is submitted through the
local SMTP relay. If no relay responds and the session is interactive, the
tool can offer to start Postfix on Linux after confirmation; this may require
sudo. If startup is declined, unavailable or unsuccessful, the spoofing test is
skipped. Submission is not proof of delivery: confirm delivery at the recipient
when prompted. Postfix started by the tool is stopped when the assessment ends,
including on errors; an already-running relay is left untouched. Messages still
queued at that point may not be delivered until Postfix is started again.

## Output

Files are written to an `email-audit` directory within the current directory.
Each assessment uses the same local timestamp (`YYYYMMDD-HHMMSS-microseconds`)
for its report and findings, for example:

- `<domain>-<timestamp>.html`: a self-contained report with control assessments, executive
  summary, technical commentary and recommendations. Use the
  per-section or combined copy controls to copy the report narrative as
  Markdown; clipboard access depends on browser permissions.
- `<domain>-<timestamp>.json`: findings, by default.

Console evidence tables are displayed when an email sample is supplied.
Each DNS check displays its raw record followed by individual field
explanations and any relevant observations. Long records wrap to fit the
terminal; the underlying values are unchanged.

## Reporting definitions

Finding descriptions are maintained in `email_audit/data/findings.yaml`.
Report narratives, control definitions and
references are in `narratives.yaml` and `reference.yaml` in the same directory.
The Python code determines which definitions apply. These packaged files are
intended for maintainers; assessment rules remain in Python.
