"""Core data model for an identity directory export.

The directory is a plain JSON document with five top-level collections
(``permissions``, ``roles``, ``groups``, ``users`` and ``title_baselines``)
plus a ``meta`` block.  Everything here is a frozen-ish dataclass with a
``from_dict`` constructor so the loader stays trivial and the analyzers can
rely on typed attributes instead of raw dict access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional, Set

SENSITIVITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PRIVILEGED_SENSITIVITIES = {"high", "critical"}


def parse_date(value: Optional[str]) -> Optional[date]:
    """Parse an ISO-8601 date or datetime string into a ``date`` (or None)."""
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).date()


@dataclass
class Permission:
    """A single entitlement, identified as ``<resource>:<action>``."""

    id: str
    resource: str
    action: str
    sensitivity: str = "low"
    description: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Permission":
        resource, _, action = raw["id"].partition(":")
        return cls(
            id=raw["id"],
            resource=raw.get("resource", resource),
            action=raw.get("action", action),
            sensitivity=raw.get("sensitivity", "low"),
            description=raw.get("description", ""),
        )

    @property
    def privileged(self) -> bool:
        return self.sensitivity in PRIVILEGED_SENSITIVITIES


@dataclass
class Role:
    """A named bundle of permissions that represents a job function."""

    id: str
    name: str
    permissions: List[str] = field(default_factory=list)
    privileged: bool = False
    description: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Role":
        return cls(
            id=raw["id"],
            name=raw.get("name", raw["id"]),
            permissions=list(raw.get("permissions", [])),
            privileged=bool(raw.get("privileged", False)),
            description=raw.get("description", ""),
        )


@dataclass
class Group:
    """A directory group. Membership grants its roles and direct permissions."""

    id: str
    name: str
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Group":
        return cls(
            id=raw["id"],
            name=raw.get("name", raw["id"]),
            roles=list(raw.get("roles", [])),
            permissions=list(raw.get("permissions", [])),
            description=raw.get("description", ""),
        )


@dataclass
class TitleRecord:
    """One entry in a user's job-title history."""

    title: str
    start: Optional[date]
    end: Optional[date]

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "TitleRecord":
        return cls(
            title=raw["title"],
            start=parse_date(raw.get("start")),
            end=parse_date(raw.get("end")),
        )


@dataclass
class User:
    """An identity (human or service account) in the directory."""

    id: str
    username: str
    display_name: str
    email: str
    department: str
    title: str
    status: str  # active | terminated | leave
    enabled: bool
    mfa_enrolled: bool
    account_type: str = "human"  # human | service
    manager_id: Optional[str] = None
    last_login: Optional[date] = None
    created: Optional[date] = None
    terminated_on: Optional[date] = None
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    direct_permissions: List[str] = field(default_factory=list)
    title_history: List[TitleRecord] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "User":
        return cls(
            id=raw["id"],
            username=raw["username"],
            display_name=raw.get("display_name", raw["username"]),
            email=raw.get("email", ""),
            department=raw.get("department", ""),
            title=raw.get("title", ""),
            status=raw.get("status", "active"),
            enabled=bool(raw.get("enabled", True)),
            mfa_enrolled=bool(raw.get("mfa_enrolled", False)),
            account_type=raw.get("account_type", "human"),
            manager_id=raw.get("manager_id"),
            last_login=parse_date(raw.get("last_login")),
            created=parse_date(raw.get("created")),
            terminated_on=parse_date(raw.get("terminated_on")),
            groups=list(raw.get("groups", [])),
            roles=list(raw.get("roles", [])),
            direct_permissions=list(raw.get("direct_permissions", [])),
            title_history=[TitleRecord.from_dict(t) for t in raw.get("title_history", [])],
        )

    @property
    def past_titles(self) -> List[str]:
        """Titles the user previously held (excluding the current one)."""
        return [t.title for t in self.title_history if t.title != self.title and t.end is not None]


@dataclass
class Grant:
    """Provenance of one effective permission: how the user ended up with it."""

    permission: str
    path: List[str]

    def path_str(self) -> str:
        return " -> ".join(self.path)


@dataclass
class Directory:
    """In-memory directory with lookups and effective-permission resolution."""

    permissions: Dict[str, Permission]
    roles: Dict[str, Role]
    groups: Dict[str, Group]
    users: Dict[str, User]
    title_baselines: Dict[str, List[str]]
    as_of: date
    meta: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ lookups
    def user_by_name(self, name: str) -> Optional[User]:
        """Find a user by id, username or email (case-insensitive)."""
        key = name.lower()
        if name in self.users:
            return self.users[name]
        for user in self.users.values():
            if user.username.lower() == key or user.email.lower() == key:
                return user
        return None

    def sensitivity(self, perm_id: str) -> str:
        perm = self.permissions.get(perm_id)
        return perm.sensitivity if perm else "low"

    def is_privileged_permission(self, perm_id: str) -> bool:
        return self.sensitivity(perm_id) in PRIVILEGED_SENSITIVITIES

    # ------------------------------------------------------- effective access
    def grants_for(self, user: User) -> List[Grant]:
        """Return every (permission, path) grant for a user, with provenance.

        Resolution order mirrors a typical RBAC directory:
        direct permissions -> direct roles -> groups (their permissions and
        their roles).  A permission can appear more than once if it is granted
        through several paths; callers that want a set use
        :meth:`effective_permissions`.
        """
        grants: List[Grant] = []
        for perm in user.direct_permissions:
            grants.append(Grant(perm, [f"user:{user.username}", "direct"]))
        for role_id in user.roles:
            role = self.roles.get(role_id)
            if role is None:
                continue
            for perm in role.permissions:
                grants.append(Grant(perm, [f"user:{user.username}", f"role:{role_id}"]))
        for group_id in user.groups:
            group = self.groups.get(group_id)
            if group is None:
                continue
            for perm in group.permissions:
                grants.append(Grant(perm, [f"user:{user.username}", f"group:{group_id}"]))
            for role_id in group.roles:
                role = self.roles.get(role_id)
                if role is None:
                    continue
                for perm in role.permissions:
                    grants.append(
                        Grant(perm, [f"user:{user.username}", f"group:{group_id}", f"role:{role_id}"])
                    )
        return grants

    def effective_permissions(self, user: User) -> Set[str]:
        """The flattened set of permissions a user can actually exercise."""
        return {g.permission for g in self.grants_for(user)}

    def effective_roles(self, user: User) -> Set[str]:
        """Roles held directly or through group membership."""
        roles = set(user.roles)
        for group_id in user.groups:
            group = self.groups.get(group_id)
            if group:
                roles.update(group.roles)
        return roles

    def baseline_for_title(self, title: str) -> Set[str]:
        """Permissions the organisation expects someone with ``title`` to hold."""
        perms: Set[str] = set()
        for role_id in self.title_baselines.get(title, []):
            role = self.roles.get(role_id)
            if role:
                perms.update(role.permissions)
        return perms

    def is_privileged_user(self, user: User) -> bool:
        """Privileged = holds a privileged role or any high/critical permission."""
        if any(self.roles[r].privileged for r in self.effective_roles(user) if r in self.roles):
            return True
        return any(self.is_privileged_permission(p) for p in self.effective_permissions(user))

    def managers(self) -> Dict[str, List[User]]:
        """Map manager id -> direct reports."""
        out: Dict[str, List[User]] = {}
        for user in self.users.values():
            if user.manager_id:
                out.setdefault(user.manager_id, []).append(user)
        return out

    def unknown_references(self) -> List[str]:
        """Dangling ids (groups/roles/permissions/managers that do not exist)."""
        problems: List[str] = []
        for user in self.users.values():
            for g in user.groups:
                if g not in self.groups:
                    problems.append(f"user {user.username} references unknown group {g}")
            for r in user.roles:
                if r not in self.roles:
                    problems.append(f"user {user.username} references unknown role {r}")
            for p in user.direct_permissions:
                if p not in self.permissions:
                    problems.append(f"user {user.username} references unknown permission {p}")
            if user.manager_id and user.manager_id not in self.users:
                problems.append(f"user {user.username} references unknown manager {user.manager_id}")
        for role in self.roles.values():
            for p in role.permissions:
                if p not in self.permissions:
                    problems.append(f"role {role.id} references unknown permission {p}")
        for group in self.groups.values():
            for r in group.roles:
                if r not in self.roles:
                    problems.append(f"group {group.id} references unknown role {r}")
        return problems


def unique(items: Iterable[str]) -> List[str]:
    """Order-preserving de-duplication helper used by several analyzers."""
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
