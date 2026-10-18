"""Access-review campaign generator.

Produces one CSV "review packet" per manager listing every entitlement held by
each of their direct reports, how it was granted, the sensitivity, the user's
risk score and any flags raised by the analyzers.  The reviewer fills in the
``decision`` column (keep / remove) and ``comment``.  Users with no usable
manager land in an ``_unassigned.csv`` packet for the IAM team.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .analyzers.risk import RiskScore
from .findings import Finding
from .models import Directory, User

PACKET_COLUMNS = [
    "campaign",
    "reviewer",
    "user_id",
    "username",
    "display_name",
    "title",
    "department",
    "account_status",
    "last_login",
    "mfa_enrolled",
    "risk_score",
    "risk_level",
    "permission",
    "sensitivity",
    "granted_via",
    "flags",
    "decision",
    "comment",
]


@dataclass
class PacketSummary:
    reviewer: str
    path: Path
    users: int
    rows: int
    flagged_rows: int


def generate_campaign(
    directory: Directory,
    findings: List[Finding],
    scores: List[RiskScore],
    out_dir: Path,
    campaign_name: str = "Q4-access-review",
    include_terminated: bool = True,
) -> List[PacketSummary]:
    """Write per-manager CSV packets to ``out_dir`` and return their summaries."""
    out_dir.mkdir(parents=True, exist_ok=True)
    score_by_user = {s.user_id: s for s in scores}
    flags_by_user: Dict[str, Dict[str, List[str]]] = {}
    for f in findings:
        per_perm = flags_by_user.setdefault(f.user_id, {})
        touched = _permissions_in_finding(f)
        key_list = touched or ["*"]
        for perm in key_list:
            per_perm.setdefault(perm, []).append(f.code)

    buckets: Dict[str, List[User]] = {}
    for user in directory.users.values():
        if user.status == "terminated" and not include_terminated:
            continue
        reviewer = _reviewer_for(directory, user)
        buckets.setdefault(reviewer, []).append(user)

    summaries: List[PacketSummary] = []
    for reviewer, users in sorted(buckets.items()):
        path = out_dir / f"{reviewer}.csv"
        rows = 0
        flagged = 0
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=PACKET_COLUMNS)
            writer.writeheader()
            for user in sorted(users, key=lambda u: (-score_by_user[u.id].score, u.username)):
                score = score_by_user[user.id]
                user_flags = flags_by_user.get(user.id, {})
                grants = directory.grants_for(user)
                by_perm: Dict[str, List[str]] = {}
                for g in grants:
                    by_perm.setdefault(g.permission, []).append(" -> ".join(g.path[1:]))
                for perm in sorted(by_perm):
                    flags = sorted(set(user_flags.get(perm, []) + user_flags.get("*", [])))
                    rows += 1
                    if flags:
                        flagged += 1
                    writer.writerow(
                        {
                            "campaign": campaign_name,
                            "reviewer": reviewer,
                            "user_id": user.id,
                            "username": user.username,
                            "display_name": user.display_name,
                            "title": user.title,
                            "department": user.department,
                            "account_status": f"{user.status}/{'enabled' if user.enabled else 'disabled'}",
                            "last_login": user.last_login.isoformat() if user.last_login else "never",
                            "mfa_enrolled": "yes" if user.mfa_enrolled else "no",
                            "risk_score": score.score,
                            "risk_level": score.level,
                            "permission": perm,
                            "sensitivity": directory.sensitivity(perm),
                            "granted_via": " | ".join(sorted(set(by_perm[perm]))),
                            "flags": ";".join(flags),
                            "decision": "",
                            "comment": "",
                        }
                    )
        summaries.append(PacketSummary(reviewer=reviewer, path=path, users=len(users), rows=rows, flagged_rows=flagged))

    _write_index(out_dir / "_index.csv", summaries, campaign_name)
    return summaries


def _permissions_in_finding(f: Finding) -> List[str]:
    """Permissions a finding is specifically about (empty = whole account)."""
    ev = f.evidence
    if "excess_permissions" in ev:
        return list(ev["excess_permissions"])
    if "creep_permissions" in ev:
        return list(ev["creep_permissions"])
    if f.category == "sod" and "paths" in ev:
        return list(ev["paths"])
    if f.code == "MFA-PRIV-MISSING":
        return list(ev.get("privileged_permissions", []))
    return []


def _reviewer_for(directory: Directory, user: User) -> str:
    manager: Optional[User] = directory.users.get(user.manager_id) if user.manager_id else None
    if manager is None or manager.status == "terminated":
        return "_unassigned"
    return manager.username


def _write_index(path: Path, summaries: List[PacketSummary], campaign: str) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["campaign", "reviewer", "packet", "users", "entitlement_rows", "flagged_rows"])
        for s in summaries:
            writer.writerow([campaign, s.reviewer, s.path.name, s.users, s.rows, s.flagged_rows])
