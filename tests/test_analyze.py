import pytest

from sg_exposure_check.analyze import DEFAULT_SENSITIVE_PORTS, analyze, classify, load_ports
from sg_exposure_check.inventory import Inventory


def perm(proto="tcp", lo=None, hi=None, v4=("0.0.0.0/0",), v6=()):
    p = {"IpProtocol": proto, "IpRanges": [{"CidrIp": c} for c in v4], "Ipv6Ranges": [{"CidrIpv6": c} for c in v6]}
    if lo is not None:
        p["FromPort"], p["ToPort"] = lo, hi if hi is not None else lo
    return p


@pytest.mark.parametrize("p, expected", [
    (perm("-1"), ("all", "all", "all-traffic", "critical")),
    (perm("tcp", 0, 65535), ("tcp", "0-65535", "all-ports", "critical")),
    (perm("6", 1, 65535), ("tcp", "1-65535", "all-ports", "critical")),
    (perm("tcp", 22), ("tcp", "22", "sensitive", "high")),
    (perm("tcp", 3000, 3400), ("tcp", "3000-3400", "sensitive", "high")),  # covers 3306 and 3389
    (perm("udp", 53), ("udp", "53", "open-port", "medium")),
    (perm("tcp", 443), ("tcp", "443", "web", "info")),
    (perm("tcp", 80, 443), ("tcp", "80-443", "sensitive", "high")),  # range includes 135, 139
    (perm("icmp", -1), ("icmp", "-", "other-protocol", "low")),
    (perm("50"), ("50", "-", "other-protocol", "low")),
])
def test_classify(p, expected):
    assert classify(p, DEFAULT_SENSITIVE_PORTS)[:4] == expected


def test_classify_lists_services():
    services = classify(perm("tcp", 3000, 3400), DEFAULT_SENSITIVE_PORTS)[4]
    assert services == ["MySQL (3306)", "RDP (3389)"]


def sg(gid, *perms):
    return {"GroupId": gid, "GroupName": gid, "VpcId": "vpc-1", "IpPermissions": list(perms)}


def eni(eid, gid, **kw):
    e = {"NetworkInterfaceId": eid, "Groups": [{"GroupId": gid}], "Description": ""}
    e.update(kw)
    return e


def test_private_cidrs_and_sg_references_ignored():
    inv = Inventory([sg("sg-1", perm("tcp", 22, v4=("10.0.0.0/8", "0.0.0.0/1")),
                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                         "UserIdGroupPairs": [{"GroupId": "sg-2"}]})], [])
    assert analyze(inv) == []


def test_unattached_capped_to_low_but_info_stays():
    inv = Inventory([sg("sg-1", perm("-1")), sg("sg-2", perm("tcp", 443))], [])
    sev = {f.group_id: f.severity for f in analyze(inv)}
    assert sev == {"sg-1": "low", "sg-2": "info"}


def test_attached_public_keeps_severity():
    inv = Inventory([sg("sg-1", perm("tcp", 22))],
                    [eni("eni-1", "sg-1", Attachment={"InstanceId": "i-1"}, Association={"PublicIp": "203.0.113.5"})])
    [f] = analyze(inv)
    assert (f.severity, f.notes) == ("high", [])
    assert f.targets[0].kind == "ec2-instance"


def test_attached_private_downgraded_per_family():
    inv = Inventory([sg("sg-1", perm("tcp", 22, v6=("::/0",)))],
                    [eni("eni-1", "sg-1", Ipv6Addresses=[{"Ipv6Address": "2001:db8::1"}])])
    sev = {f.source: f.severity for f in analyze(inv)}
    assert sev == {"0.0.0.0/0": "medium", "::/0": "high"}


def test_unknown_attachments_not_downgraded():
    inv = Inventory([sg("sg-1", perm("tcp", 22))], None)
    [f] = analyze(inv)
    assert f.severity == "high" and f.targets is None
    assert "unknown" in f.notes[0]


def test_custom_ports_and_sorting():
    inv = Inventory([sg("sg-1", perm("tcp", 8080), perm("-1"))], None)
    findings = analyze(inv, {8080: "Jenkins"})
    assert [f.severity for f in findings] == ["critical", "high"]
    assert findings[1].services == ["Jenkins (8080)"]


def test_load_ports(tmp_path):
    y = tmp_path / "p.yaml"
    y.write_text("22: SSH\n'8080': Jenkins\n")
    assert load_ports(y) == {22: "SSH", 8080: "Jenkins"}
    j = tmp_path / "p.json"
    j.write_text("[1, 2]")
    with pytest.raises(ValueError):
        load_ports(j)
