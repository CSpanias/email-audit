"""SureFormat XML export for email audit findings."""

import xml.etree.ElementTree as ET

from email_audit.reporting.definitions import load_definitions


def export_sureformat(domain, findings):
    """Write mapped findings for the assessed domain."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    item = ET.SubElement(root, "item", ipaddress="", hostname=domain)
    services = ET.SubElement(item, "services")
    service = ET.SubElement(services, "service", name="", port="", protocol="tcp")
    vulnerabilities = ET.SubElement(service, "vulnerabilities")

    exported_count = 0
    definitions = load_definitions("findings")
    for finding in findings:
        definition = definitions.get(finding["id"])
        if definition is None:
            print(f"[!] No SureFormat mapping found for finding: {finding['id']}")
            continue
        vulnerability_id = definition["sureformat_id"]
        vulnerability = ET.SubElement(vulnerabilities, "vulnerability", id=vulnerability_id)
        ET.SubElement(vulnerability, "information").text = finding["description"]
        exported_count += 1

    filename = f"{domain}.xml"
    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(filename, encoding="utf-8", xml_declaration=False)
    return filename, exported_count
