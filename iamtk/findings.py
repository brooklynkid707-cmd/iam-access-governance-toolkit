"""Shared finding type emitted by every analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """One access-governance issue tied to a user.

    ``category`` is the analyzer name (``least_privilege``, ``dormant`` ...),
    ``code`` is a stable machine-readable identifier, and ``evidence`` holds
    whatever the analyzer used to reach its conclusion so a reviewer can
    verify it without re-running the tool.
    """

    category: str
    code: str
    severity: str
    user_id: str
    username: str
    title: str
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Most severe first, then by username for stable output."""
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.username, f.code))
