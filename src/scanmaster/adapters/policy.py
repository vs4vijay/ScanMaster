from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

import yaml

from scanmaster.domain.policy import ScanPolicy


def load_policy(path: Path) -> ScanPolicy:
    if not path.exists():
        return ScanPolicy()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("scanmaster.yaml must contain a mapping")
    return ScanPolicy.model_validate(raw)


def validate_policy_target(policy: ScanPolicy, target: str) -> None:
    if policy.include_targets and not any(fnmatch(target, pattern) for pattern in policy.include_targets):
        raise ValueError("target is outside policy include_targets")
    if any(fnmatch(target, pattern) for pattern in policy.exclude_targets):
        raise ValueError("target is excluded by policy")
