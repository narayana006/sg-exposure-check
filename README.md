# sg-exposure-check

Find AWS security groups that expose sensitive ports to the internet, and show which instances, load balancers and databases they actually reach.

**Status:** works today: offline analysis of `describe-security-groups` and `describe-network-interfaces` exports, a read-only live mode (boto3, tested with [moto](https://github.com/getmoto/moto)), detection of `0.0.0.0/0` and `::/0` ingress, all-traffic and all-ports rules, a configurable sensitive-port list, attachment resolution through network interfaces, and severity that drops when nothing public is behind the group. Text and JSON output.

## Install

```bash
pip install git+https://github.com/narayana006/sg-exposure-check
```

Python 3.10 or newer. Dependencies: `boto3`, `PyYAML`.

## Quick start

[`examples/`](examples/) holds an illustrative, hand-written export for a fictional account (`123456789012`, documentation IP ranges):

```bash
sg-exposure-check -i examples/security-groups.json -i examples/network-interfaces.json
```

```text
Checked 7 security groups: 9 internet-open rules in 5 groups (1 critical, 1 high, 1 medium, 3 low, 3 info)

[CRITICAL] sg-0a1b2c3d4e5f00005 (batch-workers) tcp/0-65535 from ::/0: all-ports
    -> ec2-instance i-0a1b2c3d4e5f00005 (eni-0f0e0d0c0b0a00005, ipv6)
    -> ec2-instance i-0a1b2c3d4e5f00006 (eni-0f0e0d0c0b0a00006, ipv6)
[HIGH] sg-0a1b2c3d4e5f00001 (bastion-ssh) tcp/22 from 0.0.0.0/0: SSH (22)
    -> ec2-instance i-0a1b2c3d4e5f00001 (eni-0f0e0d0c0b0a00001, public 203.0.113.10)
[MEDIUM] sg-0a1b2c3d4e5f00003 (orders-db) tcp/5432 from 0.0.0.0/0: PostgreSQL (5432)
    -> rds RDSNetworkInterface (eni-0f0e0d0c0b0a00004)
    note: no attached interface has a public IPv4 address
[LOW] sg-0a1b2c3d4e5f00001 (bastion-ssh) icmp/- from 0.0.0.0/0: other-protocol
    -> ec2-instance i-0a1b2c3d4e5f00001 (eni-0f0e0d0c0b0a00001, public 203.0.113.10)
[LOW] sg-0a1b2c3d4e5f00004 (legacy-debug) all/all from 0.0.0.0/0: all-traffic
    note: not attached to any network interface
[LOW] sg-0a1b2c3d4e5f00005 (batch-workers) tcp/8080 from 0.0.0.0/0: open-port
    -> ec2-instance i-0a1b2c3d4e5f00005 (eni-0f0e0d0c0b0a00005, ipv6)
    -> ec2-instance i-0a1b2c3d4e5f00006 (eni-0f0e0d0c0b0a00006, ipv6)
    note: no attached interface has a public IPv4 address
[INFO] sg-0a1b2c3d4e5f00002 (web-alb) tcp/443 from 0.0.0.0/0: web
    -> alb app/web-alb/50dc6c495c0c9188 (eni-0f0e0d0c0b0a00002, public 203.0.113.21)
    -> alb app/web-alb/50dc6c495c0c9188 (eni-0f0e0d0c0b0a00003, public 203.0.113.22)
[INFO] sg-0a1b2c3d4e5f00002 (web-alb) tcp/443 from ::/0: web
    -> alb app/web-alb/50dc6c495c0c9188 (eni-0f0e0d0c0b0a00002, public 203.0.113.21)
    -> alb app/web-alb/50dc6c495c0c9188 (eni-0f0e0d0c0b0a00003, public 203.0.113.22)
    note: no attached interface has a public IPv6 address
[INFO] sg-0a1b2c3d4e5f00002 (web-alb) tcp/80 from 0.0.0.0/0: web
    -> alb app/web-alb/50dc6c495c0c9188 (eni-0f0e0d0c0b0a00002, public 203.0.113.21)
    -> alb app/web-alb/50dc6c495c0c9188 (eni-0f0e0d0c0b0a00003, public 203.0.113.22)
```

Exit code is `1` because at least one finding is `high` or worse (`--fail-on high` is the default).

## Checking your own account

Export once, analyse offline as often as you like:

```bash
aws ec2 describe-security-groups --region us-east-1 > sgs.json
aws ec2 describe-network-interfaces --region us-east-1 > enis.json
sg-exposure-check -i sgs.json -i enis.json
```

Or read live (strictly read-only) and optionally keep a snapshot of what was read:

```bash
sg-exposure-check --live --region us-east-1 --profile audit
sg-exposure-check --live --region us-east-1 --vpc-id vpc-0123456789abcdef0 --save inventory.json
sg-exposure-check -i inventory.json            # replay later, offline
```

Without network interface data the tool still flags open rules, but it cannot say what they reach and leaves severities unadjusted (it prints a warning).

## How findings are rated

Only ingress rules with a source of exactly `0.0.0.0/0` or `::/0` are reported. Rules that reference other security groups, prefix lists or narrower CIDRs are ignored.

| Category | Rule | Base severity |
|---|---|---|
| `all-traffic` | protocol `-1` (all protocols, all ports) | critical |
| `all-ports` | TCP or UDP `0-65535` (or `1-65535`) | critical |
| `sensitive` | TCP/UDP port range that includes a sensitive port | high |
| `open-port` | any other TCP/UDP port or range | medium |
| `web` | exactly port 80 or 443 | info |
| `other-protocol` | ICMP and other non-TCP/UDP protocols | low |

Then the severity is adjusted by what the group is attached to:

- **Not attached to any network interface:** capped at `low`. The rule is still a latent risk if someone attaches the group later.
- **Attached, but no attached interface has a public address of that family** (`Association.PublicIp` for IPv4 rules, any IPv6 address for `::/0` rules): lowered one level. Note this is a heuristic: traffic can still arrive through a load balancer or other path that does not use this group.
- **Attached to an interface with a public address:** unchanged.

Each finding lists the network interfaces using the group and what they belong to. That is worked out from the interface's `Attachment.InstanceId`, `InterfaceType`, `RequesterId` and the `Description` that AWS services write on interfaces they manage (for example `ELB app/<name>/<id>` for an Application Load Balancer and `RDSNetworkInterface` for RDS). Kinds recognised: `ec2-instance`, `alb`, `nlb`, `gwlb`, `elb-classic`, `rds`, `lambda`, `elasticache`, `efs`, `nat-gateway`, `vpc-endpoint`, `transit-gateway`; anything else is shown as `eni` with its raw description. RDS interfaces do not carry the DB instance identifier, so those appear as `rds RDSNetworkInterface`.

Default sensitive ports: FTP (20, 21), SSH (22), Telnet (23), SMTP (25), MS RPC (135), NetBIOS (137, 139), SMB (445), SQL Server (1433), Oracle (1521), NFS (2049), ZooKeeper (2181), Docker API (2375, 2376), MySQL (3306), RDP (3389), PostgreSQL (5432), Kibana (5601), VNC (5900), CouchDB (5984), Redis (6379), Cassandra (7001, 9042), HDFS NameNode (8020), Kafka (9092), Elasticsearch (9200, 9300), Memcached (11211), MongoDB (27017).

## Usage

```
sg-exposure-check (-i FILE [-i FILE ...] | --live) [options]

  -i, --input FILE         describe-security-groups and/or describe-network-interfaces
                           JSON; repeat for several files, '-' reads stdin
  --live                   read with ec2:DescribeSecurityGroups and
                           ec2:DescribeNetworkInterfaces
  --region, --profile      for --live
  --vpc-id VPC             --live only: restrict to one VPC
  --save FILE              --live only: write the collected inventory as JSON
  --ports-file FILE        YAML/JSON {port: label}; replaces the default list
  --port PORT[=LABEL]      add a sensitive port (repeatable), e.g. --port 8080=Jenkins
  --min-severity SEV       hide findings below info|low|medium|high|critical
  --fail-on SEV|never      exit 1 if any shown finding is at least SEV (default high)
  -f, --format text|json
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above it, `2` bad input or AWS error.

## Required permissions

`--live` only, read-only:

- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkInterfaces`

Offline mode needs no AWS access.

## Features

- [x] Offline input from AWS CLI exports (separate or combined files, stdin)
- [x] Live read-only collection with pagination, VPC filter and `--save` snapshots
- [x] Flags `0.0.0.0/0` and `::/0` ingress, all-traffic and all-ports rules
- [x] Configurable sensitive ports (`--ports-file`, `--port`)
- [x] Resolves which instances, load balancers, RDS, Lambda and other interfaces use each group
- [x] Lower severity for unattached groups and groups with no public address behind them
- [x] Text and JSON output, `--min-severity`, `--fail-on` exit codes
- [ ] Network ACL and route table checks (is the subnet actually internet-routable?)
- [ ] Multi-region scan in one run
- [ ] Flag broad but non-zero CIDRs (e.g. `/8` from outside your network)

## Limitations

- It looks at security groups only. Network ACLs, route tables, internet gateways and load balancer listeners are not evaluated, so "has a public address" is an approximation of "reachable from the internet".
- A rule open to `0.0.0.0/0` on an interface without a public IP may still be reachable through a NAT, NLB or VPC peering path; such findings are downgraded, not dropped.
- Identifying what owns an interface relies on descriptions and fields that AWS services set; unusual or future services fall back to `eni` with the raw description.
- One region per live run.

## Contributing

Issues and pull requests are welcome.

```bash
pip install -e ".[dev]"
pytest
```

Tests never contact AWS: the live path runs against moto.

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
