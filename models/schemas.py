"""Data structures and JSON report builders shared by the whole module."""
from dataclasses import dataclass, field, asdict

SCHEMA_VERSION = "1.0"
MODULE_NAME = "port_scanning_and_vulnerability_assessment"
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


@dataclass
class PortRecord:
    """One open port found by Nmap."""
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""                       # "ssl" when the service uses TLS
    nse_results: dict = field(default_factory=dict)   # script id -> output text

    def to_dict(self):
        return asdict(self)


@dataclass
class Finding:
    """One security finding, always backed by evidence from the scan."""
    title: str
    severity: str
    affected_port: int
    protocol: str
    service: str
    evidence: str
    description: str
    recommendation: str
    confidence: str
    category: str = "exposure"             # exposure | version | configuration
    id: str = ""

    def to_dict(self):
        data = asdict(self)
        # keep "id" first so the JSON is easy to read
        return {"id": data.pop("id"), **data}


def severity_summary(findings):
    """Count findings per severity level (all five levels always present)."""
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def build_port_report(metadata, ports):
    return {
        "scan_metadata": metadata,
        "ports": [p.to_dict() for p in ports],
    }


def build_vulnerability_report(metadata, findings):
    meta = dict(metadata)
    meta["total_findings"] = len(findings)
    meta["severity_summary"] = severity_summary(findings)
    return {
        "scan_metadata": meta,
        "findings": [f.to_dict() for f in findings],
    }


def base_metadata(target, address, hostname, scan_time, status, **extra):
    meta = {
        "module": MODULE_NAME,
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "resolved_address": address,
        "hostname": hostname,
        "scan_time": scan_time,
        "scanner": "Nmap",
        "status": status,
    }
    meta.update(extra)
    return meta
