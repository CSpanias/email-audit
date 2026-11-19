"""SureFormat XML export for email audit findings."""

import xml.etree.ElementTree as ET

FINDING_MAP = {
    "email-audit": "SC-2157",
    "missing-spf": "SC-2090",
    "missing-dmarc": "SC-2166",
    "missing-dkim": "SC-2165",
    "missing-mta-sts": "SC-6842",
    "invalid-mta-sts": "SC-6842",
    "permissive-spf": "SC-2183",
    "spf-processing-failure": "SC-2089",
    "email-spoofing-possible": "SC-3349",
}


def export_sureformat(domain, findings):
    """Write mapped findings for the assessed domain."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    item = ET.SubElement(root, "item", ipaddress="", hostname=domain)
    services = ET.SubElement(item, "services")
    service = ET.SubElement(services, "service", name="", port="", protocol="tcp")
    vulnerabilities = ET.SubElement(service, "vulnerabilities")

    exported_count = 0
    for finding in findings:
        vulnerability_id = FINDING_MAP.get(finding["id"])
        if not vulnerability_id:
            print(f"[!] No SureFormat mapping found for finding: {finding['id']}")
            continue
        vulnerability = ET.SubElement(vulnerabilities, "vulnerability", id=vulnerability_id)
        ET.SubElement(vulnerability, "information").text = finding["description"]
        exported_count += 1

    filename = f"{domain}.xml"
    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(filename, encoding="utf-8", xml_declaration=False)
    return filename, exported_count
