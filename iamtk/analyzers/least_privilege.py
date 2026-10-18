"""Least-privilege and privilege-creep analysis.

For each user we compare the *effective* permission set (everything reachable
through direct grants, roles and groups) with the *baseline* for the user's
current job title (``title_baselines`` in the export).  Anything outside the
baseline is excess.  Excess permissions that belong to the baseline of a title
the user previously held are reported separately as privilege creep - the
classic "transferred departments but nobody removed the old group" problem.
"""

from __future__ import annotations

from typing import Dict, List, Set

from ..findings import Finding
from ..models import Directory, User, unique


def analyze(directory: Directory) -> List[Finding]:
    """Run least-privilege and privilege-creep checks across the directory."""
    findings: List[Finding] = []
    for user in directory.users.values():
        if user.account_type != "human":
            # Service accounts are reviewed by the dormant/MFA analyzers;
            # they have no job-title baseline to compare against.
            continue
        findings.extend(analyze_user(directory, user))
    return findings


def analyze_user(directory: Directory, user: User) -> List[Finding]:
    """Return excess-permission and privilege-creep findings for one user."""
    findings: List[Finding] = []
    if user.title not in directory.title_baselines:
        findings.append(
            Finding(
                category="least_privilege",
                code="LP-NO-BASELINE",
                severity="low",
                user_id=user.id,
                username=user.username,
                title=user.title,
                detail=f"No role baseline defined for title '{user.title}'; cannot assess least privilege",
                evidence={"title": user.title},
            )
        )
        return findings

    effective = directory.effective_permissions(user)
    baseline = directory.baseline_for_title(user.title)
    excess = effective - baseline
    if not excess:
        return findings

    # Which excess permissions are explained by a previous title?
    creep: Dict[str, List[str]] = {}
    for past_title in unique(user.past_titles):
        for perm in directory.baseline_for_title(past_title) & excess:
            creep.setdefault(perm, []).append(past_title)

    plain_excess = sorted(excess - set(creep))
    grants = directory.grants_for(user)

    if plain_excess:
        max_sens = _max_sensitivity(directory, plain_excess)
        severity = {"critical": "high", "high": "high", "medium": "medium"}.get(max_sens, "low")
        findings.append(
            Finding(
                category="least_privilege",
                code="LP-EXCESS",
                severity=severity,
                user_id=user.id,
                username=user.username,
                title=user.title,
                detail=(
                    f"{len(plain_excess)} permission(s) exceed the '{user.title}' baseline "
                    f"(highest sensitivity: {max_sens})"
                ),
                evidence={
                    "excess_permissions": plain_excess,
                    "paths": {
                        p: sorted({g.path_str() for g in grants if g.permission == p}) for p in plain_excess
                    },
                    "baseline_size": len(baseline),
                    "effective_size": len(effective),
                },
            )
        )

    if creep:
        creep_perms = sorted(creep)
        max_sens = _max_sensitivity(directory, creep_perms)
        severity = "high" if max_sens in ("high", "critical") else "medium"
        past = sorted({t for titles in creep.values() for t in titles})
        findings.append(
            Finding(
                category="least_privilege",
                code="LP-CREEP",
                severity=severity,
                user_id=user.id,
                username=user.username,
                title=user.title,
                detail=(
                    f"Privilege creep: {len(creep_perms)} permission(s) retained from former title(s) "
                    f"{', '.join(past)}"
                ),
                evidence={
                    "creep_permissions": {p: creep[p] for p in creep_perms},
                    "paths": {
                        p: sorted({g.path_str() for g in grants if g.permission == p}) for p in creep_perms
                    },
                    "former_titles": past,
                },
            )
        )
    return findings


def _max_sensitivity(directory: Directory, perms: List[str]) -> str:
    order = ["low", "medium", "high", "critical"]
    best = 0
    for p in perms:
        best = max(best, order.index(directory.sensitivity(p)) if directory.sensitivity(p) in order else 0)
    return order[best]


def excess_summary(directory: Directory) -> Dict[str, Set[str]]:
    """Convenience: username -> excess permission set (used by tests/reports)."""
    out: Dict[str, Set[str]] = {}
    for user in directory.users.values():
        if user.title in directory.title_baselines:
            excess = directory.effective_permissions(user) - directory.baseline_for_title(user.title)
            if excess:
                out[user.username] = excess
    return out
