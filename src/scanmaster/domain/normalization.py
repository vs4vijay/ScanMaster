from __future__ import annotations

import hashlib
import re
from dataclasses import replace

from scanmaster.domain.runs import Finding
from scanmaster.domain.targets import Target

FINGERPRINT_VERSION = "1"


def finding_fingerprint(target: Target, finding: Finding) -> str:
    identifiers = sorted((*finding.cve_ids, *finding.cwe_ids))
    identity = "|".join(
        (
            FINGERPRINT_VERSION,
            target.canonical.lower(),
            (finding.location or "").strip().lower(),
            ",".join(value.upper() for value in identifiers),
            re.sub(r"\s+", " ", finding.title).strip().lower(),
        )
    )
    return hashlib.sha256(identity.encode()).hexdigest()


def deduplicate(target: Target, findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        fingerprint = finding_fingerprint(target, finding)
        current = merged.get(fingerprint)
        if current is None:
            merged[fingerprint] = finding
            continue
        merged[fingerprint] = replace(
            current,
            sources=tuple(sorted(set(current.sources) | set(finding.sources))),
            references=tuple(sorted(set(current.references) | set(finding.references))),
        )
    return tuple(merged[key] for key in sorted(merged))
