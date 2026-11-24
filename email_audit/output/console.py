"""Consistent Rich console output for email assessments."""

import shlex

from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def colour_assessment(value):
    if value in {"SECURE", "PRESENT", "MESSAGE SUBMITTED"}:
        style = "green"
    elif value in {"ACCEPTABLE", "UNKNOWN", "NOT APPLICABLE"}:
        style = "yellow"
    else:
        style = "red"
    return Text(value, style=style)


def rich_assessment_colour(status):
    return colour_assessment(status)


def print_info(message):
    console.print(Text.assemble(("[*]", "cyan"), f" {message}"))
    console.print()


def print_section(title):
    console.print(Text(f"\n[{title}]", style="bold cyan"))
    console.print()


def print_domain_header(domain):
    console.print(Text(f"\n{domain.upper()}\n", style="bold cyan"))


def _spf_fields(record):
    mechanisms = {
        "include": "Matches senders permitted by the referenced domain's SPF policy",
        "ip4": "Matches the specified IPv4 address or range",
        "ip6": "Matches the specified IPv6 address or range",
        "a": "Matches addresses associated with the domain",
        "mx": "Matches addresses associated with the domain's mail servers",
        "ptr": "Matches senders using reverse DNS (discouraged)",
        "exists": "Matches if the specified domain has an IPv4 address",
    }
    qualifiers = {
        "+": "pass",
        "-": "fail",
        "~": "soft failure",
        "?": "neutral result",
    }
    for field in record.split():
        if field.lower() == "v=spf1":
            yield field, "SPF record version"
            continue
        qualifier = field[0] if field[0] in qualifiers else "+"
        mechanism = field[1:] if field[0] in qualifiers else field
        if mechanism == "all":
            yield field, f"All remaining senders receive a {qualifiers[qualifier]}"
        elif mechanism.startswith("redirect="):
            yield field, "Uses the referenced domain's SPF policy if no mechanism matches"
        elif mechanism.startswith("exp="):
            yield field, "Domain providing an explanation for SPF failures"
        else:
            name = mechanism.split(":", 1)[0].split("/", 1)[0].lower()
            meaning = mechanisms.get(name)
            if meaning:
                yield field, f"{meaning}; result: {qualifiers[qualifier]}"
            else:
                yield field, "Unrecognised or unsupported SPF field"


_TAG_MEANINGS = {
    "DKIM": {
        "v": "DKIM record version",
        "k": "Public key algorithm",
        "p": "Public key used to verify signatures (shown in the record above)",
        "h": "Permitted hash algorithms",
        "s": "Permitted service types",
        "t": "Key flags",
        "n": "Notes for administrators",
    },
    "DMARC": {
        "v": "DMARC record version",
        "p": "Policy for messages that fail authentication",
        "sp": "Policy for subdomains",
        "np": "Policy for non-existent subdomains",
        "pct": "Percentage of messages to which the policy applies",
        "rua": "Destination for aggregate reports",
        "ruf": "Destination for failure reports",
        "fo": "Conditions for generating failure reports",
        "adkim": "DKIM alignment mode",
        "aspf": "SPF alignment mode",
        "rf": "Failure report format",
        "ri": "Requested aggregate reporting interval",
    },
    "MTA-STS": {
        "v": "MTA-STS record version",
        "id": "Policy identifier used to detect changes",
    },
    "TLS-RPT": {
        "v": "TLS reporting record version",
        "rua": "Destinations for email transport security reports",
    },
}


def _tag_fields(control, record):
    if control in {"DKIM", "MTA-STS"} and record.lstrip().startswith('"'):
        try:
            record = "".join(shlex.split(record))
        except ValueError:
            yield "Record", "Could not parse the quoted record into fields"
            return
    for part in record.split(";"):
        field = part.strip()
        if not field:
            continue
        name, separator, value = field.partition("=")
        name = name.strip().lower()
        if not separator:
            yield field, "Unrecognised or malformed field"
            continue
        meaning = _TAG_MEANINGS[control].get(name, "Unrecognised or unsupported field")
        if control == "DMARC" and name in {"p", "sp", "np"}:
            meaning = {
                "none": "Monitor failures without requesting enforcement",
                "quarantine": "Treat failing messages as suspicious",
                "reject": "Reject failing messages",
            }.get(value.strip().lower(), meaning + " (unrecognised value)")
        if control == "DKIM" and name == "p" and value.strip():
            field = "p=<public key>"
        yield field, meaning


def _record_fields(result):
    control, raw = result["control"], result["raw"]
    if not raw:
        return []
    if control == "SPF":
        return list(_spf_fields(raw))
    if control == "DKIM" and "v=DKIM1" not in raw:
        return []
    if control == "TLS-RPT":
        return [
            field for line in raw.splitlines() if line.startswith("v=TLSRPTv1")
            for field in _tag_fields(control, line)
        ]
    if control in _TAG_MEANINGS:
        return list(_tag_fields(control, raw))
    return []


def print_assessment(result):
    print_section(result["control"])

    if result["raw"]:
        console.print("Record", style="bold")
        console.print(Text(result["raw"]), overflow="fold")
        console.print()

    fields = _record_fields(result)
    if result["control"] == "MTA-STS":
        policy = result.get("policy", {})
        for name, meaning in (
            ("version", "Policy version"),
            ("mode", "Policy enforcement mode"),
            ("mx", "Authorised mail server"),
            ("max_age", "Policy cache duration in seconds"),
        ):
            values = policy.get(name, [])
            if isinstance(values, str):
                values = [values] if values else []
            fields.extend((f"policy: {name}={value}", meaning) for value in values)

    if fields:
        table = Table()
        table.add_column("Field", style="cyan", max_width=44, overflow="fold")
        table.add_column("Meaning", overflow="fold")
        for field, meaning in fields:
            table.add_row(Text(field), Text(meaning))
        console.print(table)

    observations = result["breakdown"] if (
        not result["raw"] or result["control"] == "DKIM"
        or result["assessment"] in {"UNKNOWN", "INVALID"}
    ) else []
    if observations:
        console.print("Observations", style="bold")
        for observation in observations:
            console.print(Text(f"  - {observation}"), overflow="fold")
    if result["assessment"] in {"UNKNOWN", "INVALID"} and result["impact"]:
        console.print(Text(f"  - {result['impact']}"), overflow="fold")


def print_completion_summary(
    findings,
    findings_file,
    html_file,
    output_format="JSON",
    exported_count=None,
):
    console.print()
    console.print(Text.assemble(("[+]", "green"), " Assessment Complete"))
    console.print()
    count = len(findings) if exported_count is None else exported_count
    for label, value in (
        ("Findings Exported", count),
        (f"{output_format} Output", findings_file),
        ("HTML Output", html_file),
    ):
        console.print(f"    {label:<17} : {value}", markup=False)
    console.print()
