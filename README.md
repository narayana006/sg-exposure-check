# sg-exposure-check

Finds AWS security group rules open to the internet (`0.0.0.0/0`, `::/0`) and tells you whether anything public is actually behind them.

Most scanners stop at "port 22 is open to the world." This one follows each rule to the network interfaces using the group, names what they are (EC2, ALB, RDS, Lambda, NAT gateway…), and lowers the severity when nothing public is attached. You get a short list of real problems instead of a long list of noise.

## Install

```bash
pip install sg-exposure-check
```

Python 3.10+.

## Use

Offline, from AWS CLI exports:

```bash
aws ec2 describe-security-groups --region us-east-1 > sgs.json
aws ec2 describe-network-interfaces --region us-east-1 > enis.json
sg-exposure-check -i sgs.json -i enis.json
```

Or live (read-only, needs only `ec2:DescribeSecurityGroups` and `ec2:DescribeNetworkInterfaces`):

```bash
sg-exposure-check --live --region us-east-1 --profile audit
```

Sample output (from [`examples/`](examples/)):

```text
Checked 7 security groups: 9 internet-open rules in 5 groups (1 critical, 1 high, 1 medium, 3 low, 3 info)

[CRITICAL] sg-0a1b2c3d4e5f00005 (batch-workers) tcp/0-65535 from ::/0: all-ports
    -> ec2-instance i-0a1b2c3d4e5f00005 (eni-0f0e0d0c0b0a00005, ipv6)
[HIGH] sg-0a1b2c3d4e5f00001 (bastion-ssh) tcp/22 from 0.0.0.0/0: SSH (22)
    -> ec2-instance i-0a1b2c3d4e5f00001 (eni-0f0e0d0c0b0a00001, public 203.0.113.10)
[MEDIUM] sg-0a1b2c3d4e5f00003 (orders-db) tcp/5432 from 0.0.0.0/0: PostgreSQL (5432)
    -> rds RDSNetworkInterface (eni-0f0e0d0c0b0a00004)
    note: no attached interface has a public IPv4 address
[LOW] sg-0a1b2c3d4e5f00004 (legacy-debug) all/all from 0.0.0.0/0: all-traffic
    note: not attached to any network interface
...
```

Useful flags: `-f json`, `--min-severity`, `--fail-on high|never` (exit code 1 on findings, for CI), `--port 8080=Jenkins`, `--vpc-id`, `--save` / replay a live snapshot. Run `sg-exposure-check -h` for all of them.

## How severity works

| Open rule | Starts at |
|---|---|
| All traffic or all ports | critical |
| Sensitive port (SSH, RDP, databases, Redis, Docker API… ~30 by default) | high |
| Any other port | medium |
| ICMP / other protocols | low |
| Only 80 or 443 | info |

Then: **not attached to anything** → capped at low. **Attached, but no public IP behind it** → down one level. **Public IP behind it** → unchanged.

## Limitations

- Security groups only. Network ACLs and route tables aren't checked, so "has a public IP" approximates "reachable."
- Private interfaces behind a NAT or NLB can still be reachable; those findings are downgraded, not dropped.
- One region per live run.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests run against [moto](https://github.com/getmoto/moto) and never touch real AWS.

## License

[MIT](LICENSE)
