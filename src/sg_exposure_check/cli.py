"""Command-line entry point for sg-exposure-check."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from . import __version__
from .analyze import DEFAULT_SENSITIVE_PORTS, SEVERITIES, analyze, load_ports
from .inventory import fetch_inventory, load_inventory
from .report import RENDERERS

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _port_arg(value: str) -> tuple[int, str]:
    port, _, label = value.partition("=")
    try:
        n = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected PORT or PORT=LABEL, got {value!r}") from None
    if not 0 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"port out of range: {n}")
    return n, label or f"port {n}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sg-exposure-check",
        description="Find security groups open to the internet and show what they actually reach.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "-i", "--input", action="append", metavar="FILE",
        help="describe-security-groups / describe-network-interfaces JSON (repeatable; '-' for stdin)",
    )
    src.add_argument("--live", action="store_true", help="read from EC2 with boto3 (read-only)")
    p.add_argument("--region", help="AWS region for --live")
    p.add_argument("--profile", help="AWS profile for --live")
    p.add_argument("--vpc-id", help="only this VPC (--live)")
    p.add_argument("--save", metavar="FILE", help="with --live, also save the collected inventory as JSON")
    p.add_argument("--ports-file", metavar="FILE", help="YAML/JSON mapping of sensitive port to label (replaces defaults)")
    p.add_argument("--port", action="append", type=_port_arg, default=[], metavar="PORT[=LABEL]",
                   help="add a sensitive port (repeatable)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this")
    p.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high",
                   help="exit 1 if any finding is at least this severity (default: high)")
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _live_client(region: str | None, profile: str | None) -> Any:
    import boto3

    return boto3.Session(profile_name=profile, region_name=region).client("ec2")


def main(argv: Sequence[str] | None = None, client: Any = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        sensitive = load_ports(args.ports_file) if args.ports_file else dict(DEFAULT_SENSITIVE_PORTS)
    except (OSError, ValueError) as exc:
        print(f"sg-exposure-check: ports file error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    sensitive.update(dict(args.port))

    try:
        if args.live:
            inv = fetch_inventory(client or _live_client(args.region, args.profile), args.vpc_id)
            if args.save:
                with open(args.save, "w", encoding="utf-8") as fh:
                    fh.write(inv.to_json())
        else:
            texts = []
            for name in args.input:
                if name == "-":
                    texts.append(sys.stdin.read())
                else:
                    with open(name, encoding="utf-8") as fh:
                        texts.append(fh.read())
            inv = load_inventory(texts)
    except (OSError, ValueError, KeyError) as exc:
        print(f"sg-exposure-check: input error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # botocore: credentials, access denied, throttling
        print(f"sg-exposure-check: AWS error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if inv.network_interfaces is None:
        print("sg-exposure-check: no NetworkInterfaces in input; cannot tell what each group reaches",
              file=sys.stderr)

    floor = SEVERITIES.index(args.min_severity)
    findings = [f for f in analyze(inv, sensitive) if SEVERITIES.index(f.severity) >= floor]
    sys.stdout.write(RENDERERS[args.format](findings, len(inv.security_groups)))

    if args.fail_on != "never":
        threshold = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) >= threshold for f in findings):
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
