"""Cross-repo dedup: groups confirmed findings that share the same LLM-assigned
vulnerability signature (independent of file/repo/language) into one group.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Finding, ValidationVerdict, new_id


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.verdict != ValidationVerdict.CONFIRMED:
            continue
        groups[(f.vuln_class, f.dedup_signature)].append(f)

    for members in groups.values():
        if len(members) < 2:
            continue
        group_id = new_id("grp")
        members.sort(key=lambda f: (f.repo, f.file, f.line))
        for i, f in enumerate(members):
            f.dedup_group_id = group_id
            f.is_dedup_primary = i == 0

    return findings
