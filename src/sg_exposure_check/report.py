"""Render findings as text or JSON."""

from __future__ import annotations

import json
from collections import Counter

from .analyze import SEVERITIES, Finding


def _target_label(t) -> str:
    parts = [t.eni_id]
    if t.public_ipv4:
        parts.append(f"public {t.public_ipv4}")
    if t.has_ipv6:
        parts.append("ipv6")
    return f"{t.kind} {t.name} ({', '.join(parts)})"


def render_text(findings: list[Finding], groups_checked: int) -> str:
    if not findings:
        return f"Checked {groups_checked} security groups: no ingress open to 0.0.0.0/0 or ::/0.\n"
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s])
    groups = len({f.group_id for f in findings})
    lines = [
        f"Checked {groups_checked} security groups: {len(findings)} internet-open rules "
        f"in {groups} groups ({summary})",
        "",
    ]
    for f in findings:
        what = f.category if not f.services else ", ".join(f.services)
        lines.append(
            f"[{f.severity.upper()}] {f.group_id} ({f.group_name}) {f.protocol}/{f.ports} "
            f"from {f.source}: {what}"
        )
        if f.targets:
            for t in f.targets:
                lines.append(f"    -> {_target_label(t)}")
        for note in f.notes:
            lines.append(f"    note: {note}")
    return "\n".join(lines) + "\n"


def render_json(findings: list[Finding], groups_checked: int) -> str:
    counts = Counter(f.severity for f in findings)
    doc = {
        "summary": {
            "groups_checked": groups_checked,
            "findings": len(findings),
            "by_severity": {s: counts[s] for s in reversed(SEVERITIES)},
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2) + "\n"


RENDERERS = {"text": render_text, "json": render_json}
