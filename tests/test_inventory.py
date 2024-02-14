import json

import pytest

from sg_exposure_check.inventory import describe_eni, load_inventory


@pytest.mark.parametrize("eni, kind, name", [
    ({"Attachment": {"InstanceId": "i-1"}}, "ec2-instance", "i-1"),
    ({"Description": "ELB app/web/abc"}, "alb", "app/web/abc"),
    ({"Description": "ELB net/nlb/abc", "InterfaceType": "network_load_balancer"}, "nlb", "net/nlb/abc"),
    ({"Description": "ELB legacy-web"}, "elb-classic", "legacy-web"),
    ({"Description": "RDSNetworkInterface", "RequesterId": "amazon-rds"}, "rds", "RDSNetworkInterface"),
    ({"Description": "AWS Lambda VPC ENI-fn-1234", "InterfaceType": "lambda"}, "lambda", "AWS Lambda VPC ENI-fn-1234"),
    ({"Description": "ElastiCache sessions-001"}, "elasticache", "sessions-001"),
    ({"Description": "Interface for NAT Gateway nat-1", "InterfaceType": "nat_gateway"}, "nat-gateway",
     "Interface for NAT Gateway nat-1"),
    ({"Description": "something custom"}, "eni", "something custom"),
    ({}, "eni", "eni-x"),
])
def test_describe_eni(eni, kind, name):
    eni = {"NetworkInterfaceId": "eni-x", **eni}
    t = describe_eni(eni)
    assert (t.kind, t.name) == (kind, name)


def test_public_addresses():
    t = describe_eni({"NetworkInterfaceId": "eni-x", "Association": {"PublicIp": "198.51.100.1"},
                      "Ipv6Addresses": [{"Ipv6Address": "2001:db8::1"}]})
    assert t.public_ipv4 == "198.51.100.1" and t.has_ipv6


def test_merge_separate_files():
    inv = load_inventory([
        json.dumps({"SecurityGroups": [{"GroupId": "sg-1"}]}),
        json.dumps({"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-1"}]}]}),
    ])
    assert inv.targets_by_group()["sg-1"][0].eni_id == "eni-1"


def test_no_eni_data_is_none():
    inv = load_inventory([json.dumps({"SecurityGroups": [{"GroupId": "sg-1"}]})])
    assert inv.targets_by_group() is None


@pytest.mark.parametrize("docs", [
    ['{"Reservations": []}'],
    ['{"NetworkInterfaces": []}'],
    ['{"SecurityGroups": [{"GroupName": "x"}]}'],
])
def test_bad_input(docs):
    with pytest.raises(ValueError):
        load_inventory(docs)
