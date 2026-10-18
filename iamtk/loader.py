"""Load a directory export (JSON) into a :class:`~iamtk.models.Directory`."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .models import Directory, Group, Permission, Role, User, parse_date

REQUIRED_SECTIONS = ("permissions", "roles", "groups", "users")


class DirectoryFormatError(ValueError):
    """Raised when the export is missing required sections or has bad ids."""


def load_directory(path: Union[str, Path], as_of: Optional[date] = None) -> Directory:
    """Read ``path`` and return a validated :class:`Directory`.

    ``as_of`` overrides the snapshot date used for dormancy calculations; by
    default it comes from ``meta.exported_at`` so reports are reproducible.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return directory_from_dict(raw, as_of=as_of)


def directory_from_dict(raw: Dict[str, Any], as_of: Optional[date] = None) -> Directory:
    """Build a :class:`Directory` from an already-parsed JSON document."""
    missing = [s for s in REQUIRED_SECTIONS if s not in raw]
    if missing:
        raise DirectoryFormatError(f"export is missing sections: {', '.join(missing)}")

    permissions = _index("permission", [Permission.from_dict(p) for p in raw["permissions"]])
    roles = _index("role", [Role.from_dict(r) for r in raw["roles"]])
    groups = _index("group", [Group.from_dict(g) for g in raw["groups"]])
    users = _index("user", [User.from_dict(u) for u in raw["users"]])

    meta = dict(raw.get("meta", {}))
    snapshot = as_of or parse_date(meta.get("exported_at")) or date.today()

    return Directory(
        permissions=permissions,
        roles=roles,
        groups=groups,
        users=users,
        title_baselines={k: list(v) for k, v in raw.get("title_baselines", {}).items()},
        as_of=snapshot,
        meta=meta,
    )


def _index(kind: str, items: list) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for item in items:
        if item.id in out:
            raise DirectoryFormatError(f"duplicate {kind} id: {item.id}")
        out[item.id] = item
    return out
