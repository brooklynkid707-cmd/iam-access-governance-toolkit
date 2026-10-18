"""RBAC policy simulator: "would user X be allowed to do Y on Z, and why?"

The simulator answers with a decision (``allow`` / ``deny``), the policy stage
that produced it, a human-readable reason and - for allows - the full grant
path (user -> group -> role -> permission).  It is the "what-if" tool for
access requests and incident questions such as *"could this account have
approved that payment?"*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from .models import Directory, User

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"


@dataclass
class Decision:
    user: str
    permission: str
    decision: str  # allow | deny
    stage: str  # account_state | deny_rule | step_up | rbac | default
    reason: str
    paths: List[str] = field(default_factory=list)
    rule_id: Optional[str] = None
    trace: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user": self.user,
            "permission": self.permission,
            "decision": self.decision,
            "stage": self.stage,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "paths": self.paths,
            "trace": self.trace,
        }


def load_policy(path: Union[str, Path, None] = None) -> Dict[str, Any]:
    policy_path = Path(path) if path else DEFAULT_POLICY_PATH
    return yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}


def simulate(
    directory: Directory,
    user: Union[User, str],
    action: str,
    resource: str,
    policy: Optional[Dict[str, Any]] = None,
) -> Decision:
    """Evaluate ``resource:action`` for ``user`` against the policy."""
    policy = policy if policy is not None else load_policy()
    permission = f"{resource}:{action}"
    if isinstance(user, str):
        found = directory.user_by_name(user)
        if found is None:
            return Decision(user, permission, "deny", "default", f"user '{user}' not found in directory")
        user = found

    trace: List[str] = []

    # 1. account state --------------------------------------------------------
    state = policy.get("account_state", {})
    if state.get("deny_terminated", True) and user.status == "terminated":
        return Decision(user.username, permission, "deny", "account_state", "account is terminated", trace=trace)
    if state.get("deny_disabled", True) and not user.enabled:
        return Decision(user.username, permission, "deny", "account_state", "account is disabled", trace=trace)
    trace.append("account_state: ok")

    # 2. explicit deny rules ----------------------------------------------------
    for rule in policy.get("deny_rules", []):
        if not fnmatchcase(permission, rule.get("permission", "")):
            continue
        if _matches(user, rule.get("when", {})):
            return Decision(
                user.username,
                permission,
                "deny",
                "deny_rule",
                f"{rule.get('name', rule.get('id'))}",
                rule_id=rule.get("id"),
                trace=trace + [f"deny_rule {rule.get('id')}: matched"],
            )
        trace.append(f"deny_rule {rule.get('id')}: condition not met")

    # 3. step-up requirements -------------------------------------------------
    sens = directory.sensitivity(permission)
    required = policy.get("step_up", {}).get("require_mfa_for_sensitivity", [])
    if sens in required and not user.mfa_enrolled:
        return Decision(
            user.username,
            permission,
            "deny",
            "step_up",
            f"permission sensitivity '{sens}' requires MFA and the user is not enrolled",
            trace=trace + ["step_up: MFA required, not enrolled"],
        )
    trace.append("step_up: ok")

    # 4. RBAC grant lookup ----------------------------------------------------
    paths = sorted({g.path_str() for g in directory.grants_for(user) if g.permission == permission})
    if paths:
        return Decision(
            user.username,
            permission,
            "allow",
            "rbac",
            f"granted via {len(paths)} path(s)",
            paths=paths,
            trace=trace + ["rbac: grant found"],
        )

    # 5. default --------------------------------------------------------------
    return Decision(
        user.username,
        permission,
        "deny" if policy.get("default", "deny") == "deny" else "allow",
        "default",
        "no role or group grants this permission",
        trace=trace + ["rbac: no grant"],
    )


def _matches(user: User, when: Dict[str, Any]) -> bool:
    """Evaluate an attribute condition block. All listed conditions must hold."""
    for key, expected in when.items():
        if key == "account_type":
            if user.account_type != expected:
                return False
        elif key == "department":
            if user.department != expected:
                return False
        elif key == "department_not_in":
            if user.department in expected:
                return False
        elif key == "department_in":
            if user.department not in expected:
                return False
        elif key == "group_not_in":
            if any(g in expected for g in user.groups):
                return False
        elif key == "group_in":
            if not any(g in expected for g in user.groups):
                return False
        elif key == "mfa_enrolled":
            if user.mfa_enrolled != bool(expected):
                return False
        else:
            raise ValueError(f"unsupported policy condition: {key}")
    return True
