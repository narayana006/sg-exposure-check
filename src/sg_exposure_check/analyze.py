"""Find internet-open ingress rules and rate them by what they actually reach."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .inventory import Inventory, Target

SEVERITIES = ["info", "low", "medium", "high", "critical"]

DEFAULT_SENSITIVE_PORTS: dict[int, str] = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "MS RPC",
    137: "NetBIOS", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server", 1521: "Oracle",
    2049: "NFS", 2181: "ZooKeeper", 2375: "Docker API", 2376: "Docker API (TLS)",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 7001: "Cassandra", 8020: "HDFS NameNode",
    9042: "Cassandra CQL", 9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}
WEB_PORTS = {80, 443}
_PROTOCOLS = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
WORLD = {"0.0.0.0/0": "ipv4", "::/0": "ipv6"}


@dataclass
class Finding:
    group_id: str
    group_name: str
    vpc_id: str
    protocol: str
    ports: str
    source: str
    category: str  # all-traffic | all-ports | sensitive | open-port | web | other-protocol
    severity: str
    services: list[str]
    targets: list[Target] | None  # None: network interfaces not collected
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "vpc_id": self.vpc_id,
            "protocol": self.protocol,
            "ports": self.ports,
            "source": self.source,
            "category": self.category,
            "severity": self.severity,
            "services": self.services,
            "targets": None if self.targets is None else [t.to_dict() for t in self.targets],
            "notes": self.notes,
        }


def load_ports(path: str | Path) -> dict[int, str]:
    """Load a {port: label} mapping from JSON or YAML (``22: SSH``)."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        raw = json.loads(text)
    else:
        import yaml

        raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping of port to label")
    return {int(k): str(v) for k, v in raw.items()}


def _shift(severity: str, by: int, floor: str = "info") -> str:
    idx = max(SEVERITIES.index(severity) + by, SEVERITIES.index(floor))
    return SEVERITIES[min(idx, len(SEVERITIES) - 1)]


def classify(perm: dict[str, Any], sensitive: dict[int, str]) -> tuple[str, str, str, str, list[str]]:
    """Return (protocol, ports, category, base severity, matched service labels) for a rule."""
    proto = _PROTOCOLS.get(str(perm.get("IpProtocol", "-1")), str(perm.get("IpProtocol")))
    if proto == "all":
        return "all", "all", "all-traffic", "critical", []
    if proto not in ("tcp", "udp"):
        return proto, "-", "other-protocol", "low", []
    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    if lo is None or hi is None or lo < 0 or hi < 0:
        lo, hi = 0, 65535
    ports = str(lo) if lo == hi else f"{lo}-{hi}"
    if lo <= 1 and hi >= 65535:
        return proto, ports, "all-ports", "critical", []
    hits = [f"{sensitive[p]} ({p})" for p in sorted(sensitive) if lo <= p <= hi]
    if hits:
        return proto, ports, "sensitive", "high", hits
    if lo == hi and lo in WEB_PORTS:
        return proto, ports, "web", "info", []
    return proto, ports, "open-port", "medium", []


def _world_sources(perm: dict[str, Any]) -> list[str]:
    found = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
    found += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
    return found


def _reachable(t: Target, family: str) -> bool:
    return bool(t.public_ipv4) if family == "ipv4" else t.has_ipv6


def analyze(inv: Inventory, sensitive: dict[int, str] | None = None) -> list[Finding]:
    sensitive = DEFAULT_SENSITIVE_PORTS if sensitive is None else sensitive
    by_group = inv.targets_by_group()
    findings: list[Finding] = []
    for sg in inv.security_groups:
        gid = sg["GroupId"]
        targets = None if by_group is None else by_group.get(gid, [])
        for perm in sg.get("IpPermissions", []):
            for source in _world_sources(perm):
                proto, ports, category, severity, services = classify(perm, sensitive)
                notes: list[str] = []
                if targets is None:
                    notes.append("attachments unknown (no network interface data)")
                elif not targets:
                    if SEVERITIES.index(severity) > SEVERITIES.index("low"):
                        severity = "low"
                    notes.append("not attached to any network interface")
                elif not any(_reachable(t, WORLD[source]) for t in targets):
                    family = "IPv4" if WORLD[source] == "ipv4" else "IPv6"
                    severity = _shift(severity, -1)
                    notes.append(f"no attached interface has a public {family} address")
                findings.append(Finding(
                    group_id=gid,
                    group_name=sg.get("GroupName", ""),
                    vpc_id=sg.get("VpcId", "-"),
                    protocol=proto,
                    ports=ports,
                    source=source,
                    category=category,
                    severity=severity,
                    services=services,
                    targets=targets,
                    notes=notes,
                ))
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.group_id, f.ports, f.source))
    return findings
