# Installation

Email Audit requires Python 3.10 or later. DNS queries and
MTA-STS policy retrieval require network access.

## Install with uv

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run:

```bash
uv tool install git+https://github.com/CSpanias/email-audit
email-audit --help
```

Update with `uv tool upgrade email-audit`.

## Install from a clone

```bash
git clone https://github.com/CSpanias/email-audit
cd email-audit
python -m pip install .
email-audit --help
```

For development, install with `python -m pip install -e ".[docs]"`, run
`python -m unittest discover -s tests`, and build this site with
`python -m mkdocs build --strict`.

## Optional tools

- `msgconvert` is required for Outlook `.msg` files. On Debian-based systems
  it is provided by `libemail-outlook-message-perl`.
- `swaks` and a local SMTP relay listening on port 25 are required for
  controlled spoofing tests.
