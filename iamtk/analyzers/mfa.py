"""MFA compliance analysis.

* Privileged users (privileged role or any high/critical permission) without
  MFA are **critical** - this is the exact population that T1078 Valid Accounts
  abuse targets, and a single phished password is enough to compromise them.
* Non-privileged humans without MFA are **medium**.
* Service accounts are excluded from the MFA requirement (they should be
  using keys/certificates) but are listed in the summary so they can be
  reviewed separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..findings import Finding
from ..models import Directory


@dataclass
class MfaSummary:
    """Roll-up numbers for the MFA section of the report."""

    humans_total: int = 0
    humans_enrolled: int = 0
    privileged_total: int = 0
    privileged_enrolled: int = 0
    service_accounts: int = 0
    unenrolled_by_department: Dict[str, int] = field(default_factory=dict)

    @property
    def human_coverage(self) -> float:
        return (self.humans_enrolled / self.humans_total * 100) if self.humans_total else 100.0

    @property
    def privileged_coverage(self) -> float:
        return (self.privileged_enrolled / self.privileged_total * 100) if self.privileged_total else 100.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "humans_total": self.humans_total,
            "humans_enrolled": self.humans_enrolled,
            "human_coverage_pct": round(self.human_coverage, 1),
            "privileged_total": self.privileged_total,
            "privileged_enrolled": self.privileged_enrolled,
            "privileged_coverage_pct": round(self.privileged_coverage, 1),
            "service_accounts": self.service_accounts,
            "unenrolled_by_department": dict(sorted(self.unenrolled_by_department.items())),
        }


def analyze(directory: Directory) -> List[Finding]:
    return analyze_with_summary(directory)[0]


def analyze_with_summary(directory: Directory) -> tuple[List[Finding], MfaSummary]:
    """Return MFA findings plus coverage statistics."""
    findings: List[Finding] = []
    summary = MfaSummary()
    for user in directory.users.values():
        if user.account_type != "human":
            summary.service_accounts += 1
            continue
        if user.status == "terminated" or not user.enabled:
            continue  # handled by the dormant analyzer; no point nagging about MFA
        privileged = directory.is_privileged_user(user)
        summary.humans_total += 1
        if privileged:
            summary.privileged_total += 1
        if user.mfa_enrolled:
            summary.humans_enrolled += 1
            if privileged:
                summary.privileged_enrolled += 1
            continue

        summary.unenrolled_by_department[user.department] = (
            summary.unenrolled_by_department.get(user.department, 0) + 1
        )
        priv_perms = sorted(
            p for p in directory.effective_permissions(user) if directory.is_privileged_permission(p)
        )
        findings.append(
            Finding(
                category="mfa",
                code="MFA-PRIV-MISSING" if privileged else "MFA-MISSING",
                severity="critical" if privileged else "medium",
                user_id=user.id,
                username=user.username,
                title=user.title,
                detail=(
                    f"Privileged user without MFA ({len(priv_perms)} high/critical permission(s))"
                    if privileged
                    else "User has not enrolled in MFA"
                ),
                evidence={"privileged": privileged, "privileged_permissions": priv_perms},
            )
        )
    return findings, summary
