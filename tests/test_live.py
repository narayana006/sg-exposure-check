"""--live path against moto's EC2 (no real AWS)."""

import json

import boto3

from sg_exposure_check.cli import main
from sg_exposure_check.inventory import fetch_inventory


def _setup():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    ssh = ec2.create_security_group(GroupName="ssh-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=ssh, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    unused = ec2.create_security_group(GroupName="unused-all", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=unused, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    inst = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, SubnetId=subnet,
                             SecurityGroupIds=[ssh])["Instances"][0]["InstanceId"]
    return ec2, vpc, ssh, unused, inst


def test_fetch_inventory(moto_env):
    ec2, vpc, ssh, unused, inst = _setup()
    inv = fetch_inventory(ec2, vpc)
    ids = {g["GroupId"] for g in inv.security_groups}
    assert {ssh, unused} <= ids
    targets = inv.targets_by_group()
    assert [t.name for t in targets[ssh]] == [inst]
    assert unused not in targets


def test_cli_live_and_save(moto_env, tmp_path, capsys):
    ec2, vpc, ssh, unused, inst = _setup()
    saved = tmp_path / "inv.json"
    code = main(["--live", "--vpc-id", vpc, "-f", "json", "--save", str(saved)], client=ec2)
    doc = json.loads(capsys.readouterr().out)
    by_group = {f["group_name"]: f for f in doc["findings"]}
    assert by_group["unused-all"]["severity"] == "low"
    # moto instances in a fresh subnet have no public IP, so SSH is downgraded one level
    assert by_group["ssh-open"]["targets"][0]["name"] == inst
    assert by_group["ssh-open"]["severity"] == "medium"
    assert code == 0  # nothing at or above the default --fail-on high
    # the saved inventory replays offline with identical findings
    assert main(["-i", str(saved), "-f", "json"]) == code
    assert json.loads(capsys.readouterr().out)["findings"] == doc["findings"]
