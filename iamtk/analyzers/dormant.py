"""Orphaned and dormant account detection.

Checks (all evaluated against the export's ``as_of`` date):

* ``DORM-NO-LOGIN``        enabled account with no successful login in
                           ``dormant_days`` days (default 90) or never.
* ``DORM-TERMINATED``      HR status is *terminated* but the account is still
                           enabled - the single most common offboarding gap.
* ``DORM-DISABLED-ACCESS`` disabled account that still holds privileged access
                           (a re-enable away from being a live threat).
* ``ORPHAN-NO-MANAGER``    no manager recorded, so nobody can attest to the
                           access in a review campaign.
* ``ORPHAN-MANAGER-GONE``  manager id points at a terminated or missing user.
"""

from __future__ import annotations

from typing import List

from ..findings import Finding
from ..models import Directory, User

DEFAULT_DORMANT_DAYS = 90


def analyze(directory: Directory, dormant_days: int = DEFAULT_DORMANT_DAYS) -> List[Finding]:
    findings: List[Finding] = []
    for user in directory.users.values():
        findings.extend(analyze_user(directory, user, dormant_days))
    return findings


def analyze_user(directory: Directory, user: User, dormant_days: int = DEFAULT_DORMANT_DAYS) -> List[Finding]:
    findings: List[Finding] = []
    privileged = directory.is_privileged_user(user)
    base = dict(user_id=user.id, username=user.username, title=user.title)

    # --- terminated but still enabled -------------------------------------
    if user.status == "terminated" and user.enabled:
        days = (directory.as_of - user.terminated_on).days if user.terminated_on else None
        findings.append(
            Finding(
                category="dormant",
                code="DORM-TERMINATED",
                severity="critical" if privileged else "high",
                detail=(
                    "Account is still enabled although HR status is terminated"
                    + (f" ({days} days ago)" if days is not None else "")
                    + (" and the account holds privileged access" if privileged else "")
                ),
                evidence={
                    "terminated_on": user.terminated_on.isoformat() if user.terminated_on else None,
                    "days_since_termination": days,
                    "privileged": privileged,
                },
                **base,
            )
        )

    # --- dormant (no recent login) ----------------------------------------
    if user.enabled and user.status != "terminated":
        if user.last_login is None:
            days_idle = (directory.as_of - user.created).days if user.created else None
            if days_idle is None or days_idle > dormant_days:
                findings.append(
                    Finding(
                        category="dormant",
                        code="DORM-NO-LOGIN",
                        severity="high" if privileged else "medium",
                        detail="Enabled account has never logged in"
                        + (f" (created {days_idle} days ago)" if days_idle is not None else ""),
                        evidence={"last_login": None, "days_idle": days_idle, "privileged": privileged},
                        **base,
                    )
                )
        else:
            days_idle = (directory.as_of - user.last_login).days
            if days_idle > dormant_days:
                findings.append(
                    Finding(
                        category="dormant",
                        code="DORM-NO-LOGIN",
                        severity="high" if privileged else "medium",
                        detail=f"No login for {days_idle} days (threshold {dormant_days})",
                        evidence={
                            "last_login": user.last_login.isoformat(),
                            "days_idle": days_idle,
                            "privileged": privileged,
                        },
                        **base,
                    )
                )

    # --- disabled but still entitled --------------------------------------
    if not user.enabled and privileged:
        findings.append(
            Finding(
                category="dormant",
                code="DORM-DISABLED-ACCESS",
                severity="medium",
                detail="Disabled account still holds privileged entitlements; remove access, not just the login",
                evidence={"privileged_permissions": sorted(
                    p for p in directory.effective_permissions(user) if directory.is_privileged_permission(p)
                )},
                **base,
            )
        )

    # --- orphaned (no accountable owner) -----------------------------------
    if user.status != "terminated":
        if not user.manager_id:
            findings.append(
                Finding(
                    category="orphan",
                    code="ORPHAN-NO-MANAGER",
                    severity="medium" if privileged else "low",
                    detail="No manager/owner recorded - access cannot be attested in a review",
                    evidence={"account_type": user.account_type, "privileged": privileged},
                    **base,
                )
            )
        else:
            manager = directory.users.get(user.manager_id)
            if manager is None or manager.status == "terminated":
                findings.append(
                    Finding(
                        category="orphan",
                        code="ORPHAN-MANAGER-GONE",
                        severity="medium",
                        detail=(
                            f"Manager {user.manager_id} is "
                            + ("missing from the directory" if manager is None else "terminated")
                        ),
                        evidence={"manager_id": user.manager_id, "manager_status": manager.status if manager else None},
                        **base,
                    )
                )
    return findings
