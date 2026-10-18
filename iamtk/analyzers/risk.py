"""Per-user risk scoring (0-100) with explainable reasons.

The score is additive over the findings the other analyzers produced, with a
per-category cap so one noisy category (e.g. many small excess permissions)
cannot drown out a single critical issue.  Every point is tied to a reason
string, so the report can show *why* a user scored what they did.

Weights are intentionally simple and visible (see ``WEIGHTS``) - the point of
a governance score is that an auditor can defend it, not that it is clever.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..findings import Finding
from ..models import Directory, User

# code -> (points per finding, cap for that code)
WEIGHTS: Dict[str, tuple[int, int]] = {
    "MFA-PRIV-MISSING": (40, 40),
    "MFA-MISSING": (10, 10),
    "DORM-TERMINATED": (35, 35),
    "DORM-NO-LOGIN": (15, 15),
    "DORM-DISABLED-ACCESS": (10, 10),
    "ORPHAN-NO-MANAGER": (10, 10),
    "ORPHAN-MANAGER-GONE": (8, 8),
    "LP-EXCESS": (0, 20),  # scored per permission below
    "LP-CREEP": (0, 15),  # scored per permission below
    "LP-NO-BASELINE": (3, 3),
}
SOD_POINTS = {"critical": 20, "high": 15, "medium": 10, "low": 5}
SOD_CAP = 40
EXCESS_POINTS_PER_PERM = {"critical": 8, "high": 5, "medium": 3, "low": 2}
CREEP_POINTS_PER_PERM = {"critical": 8, "high": 5, "medium": 3, "low": 2}
PRIVILEGED_BASE = 5  # being privileged at all adds a small amount of inherent risk


@dataclass
class RiskScore:
    user_id: str
    username: str
    display_name: str
    department: str
    title: str
    score: int
    level: str
    reasons: List[str] = field(default_factory=list)
    finding_codes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "department": self.department,
            "title": self.title,
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
            "finding_codes": self.finding_codes,
        }


def level_for(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def score_users(directory: Directory, findings: List[Finding]) -> List[RiskScore]:
    """Compute a risk score for every user, highest first."""
    by_user: Dict[str, List[Finding]] = {}
    for f in findings:
        by_user.setdefault(f.user_id, []).append(f)
    scores = [score_user(directory, user, by_user.get(user.id, [])) for user in directory.users.values()]
    scores.sort(key=lambda s: (-s.score, s.username))
    return scores


def score_user(directory: Directory, user: User, findings: List[Finding]) -> RiskScore:
    """Score one user from their findings. Deterministic and fully explained."""
    total = 0
    reasons: List[str] = []
    per_code: Dict[str, int] = {}
    sod_total = 0

    if directory.is_privileged_user(user) and user.enabled:
        total += PRIVILEGED_BASE
        reasons.append(f"+{PRIVILEGED_BASE} holds privileged access (inherent)")

    for f in findings:
        if f.category == "sod":
            pts = SOD_POINTS.get(f.severity, 5)
            allowed = max(0, min(pts, SOD_CAP - sod_total))
            sod_total += allowed
            if allowed:
                total += allowed
                reasons.append(f"+{allowed} SoD conflict {f.code}: {f.evidence.get('rule', f.detail)}")
            continue

        if f.code == "LP-EXCESS":
            pts = sum(
                EXCESS_POINTS_PER_PERM.get(directory.sensitivity(p), 2)
                for p in f.evidence.get("excess_permissions", [])
            )
            allowed = min(pts, WEIGHTS["LP-EXCESS"][1])
            total += allowed
            reasons.append(
                f"+{allowed} {len(f.evidence.get('excess_permissions', []))} permission(s) beyond title baseline"
            )
            continue

        if f.code == "LP-CREEP":
            creep = f.evidence.get("creep_permissions", {})
            pts = sum(CREEP_POINTS_PER_PERM.get(directory.sensitivity(p), 2) for p in creep)
            allowed = min(pts, WEIGHTS["LP-CREEP"][1])
            total += allowed
            reasons.append(
                f"+{allowed} privilege creep: {len(creep)} permission(s) from former title(s) "
                f"{', '.join(f.evidence.get('former_titles', []))}"
            )
            continue

        pts, cap = WEIGHTS.get(f.code, (5, 5))
        used = per_code.get(f.code, 0)
        allowed = max(0, min(pts, cap - used))
        per_code[f.code] = used + allowed
        if allowed:
            total += allowed
            reasons.append(f"+{allowed} {f.code}: {f.detail}")

    score = max(0, min(100, total))
    return RiskScore(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        department=user.department,
        title=user.title,
        score=score,
        level=level_for(score),
        reasons=reasons,
        finding_codes=sorted({f.code for f in findings}),
    )
