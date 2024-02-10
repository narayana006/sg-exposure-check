"""Security group and network interface inventory: offline JSON or live EC2 reads."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# Interface descriptions written by AWS services when they create an ENI for you.
_ELB_KINDS = {"app/": "alb", "net/": "nlb", "gwy/": "gwlb"}
_INTERFACE_TYPES = {
    "lambda": "lambda",
    "nat_gateway": "nat-gateway",
    "vpc_endpoint": "vpc-endpoint",
    "network_load_balancer": "nlb",
    "gateway_load_balancer": "gwlb",
    "gateway_load_balancer_endpoint": "gwlb-endpoint",
    "transit_gateway": "transit-gateway",
}


@dataclass
class Target:
    """Something a security group is attached to, seen through its network interface."""

    eni_id: str
    kind: str  # ec2-instance, alb, nlb, elb-classic, rds, lambda, ... or "eni"
    name: str
    public_ipv4: str | None = None
    has_ipv6: bool = False
    private_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "eni_id": self.eni_id,
            "kind": self.kind,
            "name": self.name,
            "public_ipv4": self.public_ipv4,
            "has_ipv6": self.has_ipv6,
            "private_ip": self.private_ip,
        }


@dataclass
class Inventory:
    security_groups: list[dict[str, Any]] = field(default_factory=list)
    network_interfaces: list[dict[str, Any]] | None = None  # None: not collected

    def merge(self, other: "Inventory") -> None:
        self.security_groups.extend(other.security_groups)
        if other.network_interfaces is not None:
            self.network_interfaces = (self.network_interfaces or []) + other.network_interfaces

    def targets_by_group(self) -> dict[str, list[Target]] | None:
        if self.network_interfaces is None:
            return None
        out: dict[str, list[Target]] = {}
        for eni in self.network_interfaces:
            target = describe_eni(eni)
            for g in eni.get("Groups", []):
                out.setdefault(g["GroupId"], []).append(target)
        return out

    def to_json(self) -> str:
        doc: dict[str, Any] = {"SecurityGroups": self.security_groups}
        if self.network_interfaces is not None:
            doc["NetworkInterfaces"] = self.network_interfaces
        return json.dumps(doc, indent=2, default=str) + "\n"


def describe_eni(eni: dict[str, Any]) -> Target:
    """Work out what an ENI belongs to from its attachment, type, requester and description."""
    desc = (eni.get("Description") or "").strip()
    itype = eni.get("InterfaceType") or "interface"
    attachment = eni.get("Attachment") or {}
    kind, name = "eni", desc or eni.get("NetworkInterfaceId", "?")

    if attachment.get("InstanceId"):
        kind, name = "ec2-instance", attachment["InstanceId"]
    elif desc.startswith("ELB "):
        rest = desc[4:]
        kind = next((k for prefix, k in _ELB_KINDS.items() if rest.startswith(prefix)), "elb-classic")
        name = rest
    elif desc == "RDSNetworkInterface" or eni.get("RequesterId") == "amazon-rds":
        kind = "rds"
    elif itype == "lambda" or desc.startswith("AWS Lambda VPC ENI"):
        kind = "lambda"
    elif desc.startswith("ElastiCache "):
        kind, name = "elasticache", desc.split(" ", 1)[1]
    elif re.match(r"EFS mount target for fs-", desc):
        kind = "efs"
    elif itype in _INTERFACE_TYPES:
        kind = _INTERFACE_TYPES[itype]

    assoc = eni.get("Association") or {}
    ipv6 = eni.get("Ipv6Addresses") or []
    return Target(
        eni_id=eni.get("NetworkInterfaceId", "?"),
        kind=kind,
        name=name,
        public_ipv4=assoc.get("PublicIp"),
        has_ipv6=bool(ipv6) or bool(eni.get("Ipv6Address")),
        private_ip=eni.get("PrivateIpAddress"),
    )


def parse_inventory(doc: Any) -> Inventory:
    """Accept ``describe-security-groups`` and/or ``describe-network-interfaces`` output."""
    if not isinstance(doc, dict) or not ({"SecurityGroups", "NetworkInterfaces"} & set(doc)):
        raise ValueError(
            "expected 'aws ec2 describe-security-groups' or 'describe-network-interfaces' JSON "
            "(an object with SecurityGroups and/or NetworkInterfaces)"
        )
    sgs = doc.get("SecurityGroups") or []
    for sg in sgs:
        if "GroupId" not in sg:
            raise ValueError("security group entry without GroupId")
    enis = doc.get("NetworkInterfaces")
    return Inventory(security_groups=list(sgs), network_interfaces=list(enis) if enis is not None else None)


def load_inventory(texts: list[str]) -> Inventory:
    inv = Inventory()
    for text in texts:
        inv.merge(parse_inventory(json.loads(text)))
    if not inv.security_groups:
        raise ValueError("no security groups in input")
    return inv


def fetch_inventory(ec2: Any, vpc_id: str | None = None) -> Inventory:
    """Read security groups and network interfaces with a boto3 EC2 client (read-only)."""
    filters = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
    sgs: list[dict[str, Any]] = []
    for page in ec2.get_paginator("describe_security_groups").paginate(Filters=filters):
        sgs.extend(page.get("SecurityGroups", []))
    enis: list[dict[str, Any]] = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate(Filters=filters):
        enis.extend(page.get("NetworkInterfaces", []))
    return Inventory(security_groups=sgs, network_interfaces=enis)
