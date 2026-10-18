"""Separation-of-duties (SoD) conflict detection.

Rules live in a YAML file (see ``config/sod_rules.yaml``).  Each rule names a
*toxic combination* of permissions; a user who holds every permission in the
combination is in conflict.  Besides per-user findings the analyzer builds a
conflict matrix (rule x rule overlap and permission-pair counts) that the
report renders so auditors can see where the toxic combinations cluster.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from ..findings import Finding
from ..models import Directory, User

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "config" / "sod_rules.yaml"


@dataclass
class SodRule:
    id: str
    name: str
    permissions: List[str]
    severity: str = "high"
    description: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SodRule":
        perms = list(raw.get("permissions", []))
        if len(perms) < 2:
            raise ValueError(f"SoD rule {raw.get('id')} needs at least two permissions")
        return cls(
            id=str(raw["id"]),
            name=raw.get("name", raw["id"]),
            permissions=perms,
            severity=raw.get("severity", "high"),
            description=str(raw.get("description", "")).strip(),
        )


@dataclass
class SodMatrix:
    """Aggregated view of conflicts for the report."""

    rule_hits: Dict[str, int] = field(default_factory=dict)  # rule id -> users in conflict
    rule_users: Dict[str, List[str]] = field(default_factory=dict)
    pair_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)  # (permA, permB) -> users

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_hits": self.rule_hits,
            "rule_users": self.rule_users,
            "permission_pairs": [
                {"permissions": list(pair), "users": count}
                for pair, count in sorted(self.pair_counts.items(), key=lambda kv: -kv[1])
            ],
        }


def load_rules(path: Union[str, Path, None] = None) -> List[SodRule]:
    """Load SoD rules from YAML (defaults to the bundled rule set)."""
    rules_path = Path(path) if path else DEFAULT_RULES_PATH
    raw = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    return [SodRule.from_dict(r) for r in raw.get("rules", [])]


def analyze(directory: Directory, rules: Optional[List[SodRule]] = None) -> List[Finding]:
    return analyze_with_matrix(directory, rules)[0]


def analyze_with_matrix(
    directory: Directory, rules: Optional[List[SodRule]] = None
) -> Tuple[List[Finding], SodMatrix]:
    """Evaluate every rule against every user; return findings plus the matrix."""
    rules = rules if rules is not None else load_rules()
    findings: List[Finding] = []
    matrix = SodMatrix(rule_hits={r.id: 0 for r in rules}, rule_users={r.id: [] for r in rules})

    for user in directory.users.values():
        if user.status == "terminated" and not user.enabled:
            continue  # fully offboarded; nothing to exercise
        effective = directory.effective_permissions(user)
        for rule in rules:
            findings.extend(_check_rule(directory, user, rule, effective, matrix))
    return findings, matrix


def _check_rule(directory: Directory, user: User, rule: SodRule, effective: set, matrix: SodMatrix) -> List[Finding]:
    if not set(rule.permissions).issubset(effective):
        return []
    matrix.rule_hits[rule.id] += 1
    matrix.rule_users[rule.id].append(user.username)
    for pair in combinations(sorted(rule.permissions), 2):
        matrix.pair_counts[pair] = matrix.pair_counts.get(pair, 0) + 1

    grants = directory.grants_for(user)
    paths = {p: sorted({g.path_str() for g in grants if g.permission == p}) for p in rule.permissions}
    # If every conflicting permission comes through the same single role the
    # fix is a role redesign, not a user-level removal; call that out.
    sources = {tuple(v) for v in paths.values()}
    same_source = len(sources) == 1
    return [
        Finding(
            category="sod",
            code=rule.id,
            severity=rule.severity,
            user_id=user.id,
            username=user.username,
            title=user.title,
            detail=f"SoD conflict '{rule.name}': holds {' + '.join(rule.permissions)}"
            + (" (all via the same assignment - fix the role, not the user)" if same_source else ""),
            evidence={"rule": rule.name, "description": rule.description, "paths": paths, "same_source": same_source},
        )
    ]
