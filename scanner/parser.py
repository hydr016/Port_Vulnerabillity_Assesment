"""Turns Nmap XML output into plain Python data."""
import xml.etree.ElementTree as ET

from models.schemas import PortRecord


class ParseError(Exception):
    """Raised when Nmap output is malformed or unexpected."""


def parse_nmap_xml(xml_text):
    """Return {"host_up", "address", "hostname", "nmap_version", "ports"}."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ParseError(f"Nmap returned output that could not be read ({exc}).")
    if root.tag != "nmaprun":
        raise ParseError("Unexpected Nmap output format.")

    result = {"host_up": False, "address": "", "hostname": "",
              "nmap_version": root.get("version", ""), "ports": []}

    host = root.find("host")
    if host is None:
        return result
    status = host.find("status")
    result["host_up"] = status is not None and status.get("state") == "up"

    addr = host.find("address")
    if addr is not None:
        result["address"] = addr.get("addr", "")
    name = host.find("hostnames/hostname")
    if name is not None:
        result["hostname"] = name.get("name", "")

    for port_el in host.findall("ports/port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue                      # only OPEN ports are reported
        try:
            number = int(port_el.get("portid", ""))
        except ValueError:
            continue
        service = port_el.find("service")
        svc = service.attrib if service is not None else {}
        scripts = {s.get("id", "unknown"): (s.get("output") or "").strip()
                   for s in port_el.findall("script")}
        result["ports"].append(PortRecord(
            port=number,
            protocol=port_el.get("protocol", "tcp"),
            state="open",
            service=svc.get("name", ""),
            product=svc.get("product", ""),
            version=svc.get("version", ""),
            extra_info=svc.get("extrainfo", ""),
            tunnel=svc.get("tunnel", ""),
            nse_results=scripts,
        ))
    result["ports"].sort(key=lambda p: (p.protocol, p.port))
    return result
