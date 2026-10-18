"""Shared fixtures: a tiny hand-built directory with one of every problem."""

from __future__ import annotations

from datetime import date
from typing import Any, Dict

import pytest

from iamtk.loader import directory_from_dict
from iamtk.models import Directory

AS_OF = date(2026, 10, 15)


def _user(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "id": overrides["id"],
        "username": overrides.get("username", overrides["id"]),
        "display_name": overrides.get("username", overrides["id"]).title(),
        "email": f"{overrides.get('username', overrides['id'])}@example.com",
        "department": "Finance",
        "title": "Accounts Payable Clerk",
        "account_type": "human",
        "status": "active",
        "enabled": True,
        "mfa_enrolled": True,
        "manager_id": "mgr",
        "created": "2022-01-10",
        "last_login": "2026-10-10",
        "groups": ["g-all", "g-ap-clerk"],
        "roles": [],
        "direct_permissions": [],
        "title_history": [],
    }
    base.update(overrides)
    return base


@pytest.fixture
def raw_directory() -> Dict[str, Any]:
    return {
        "meta": {"exported_at": AS_OF.isoformat(), "source": "unit-test"},
        "permissions": [
            {"id": "corp.email:use", "sensitivity": "low"},
            {"id": "finance.vendors:read", "sensitivity": "low"},
            {"id": "finance.vendors:create", "sensitivity": "high"},
            {"id": "finance.payments:create", "sensitivity": "medium"},
            {"id": "finance.payments:approve", "sensitivity": "critical"},
            {"id": "it.iam:admin", "sensitivity": "critical"},
            {"id": "sales.crm:read", "sensitivity": "low"},
            {"id": "sales.crm:export", "sensitivity": "high"},
        ],
        "roles": [
            {"id": "employee", "name": "Employee", "permissions": ["corp.email:use"]},
            {"id": "ap_clerk", "name": "AP Clerk", "permissions": ["finance.vendors:read", "finance.payments:create"]},
            {"id": "ap_manager", "name": "AP Manager", "permissions": ["finance.vendors:read", "finance.payments:approve"]},
            {"id": "procurement", "name": "Procurement", "permissions": ["finance.vendors:read", "finance.vendors:create"]},
            {"id": "iam_admin", "name": "IAM Admin", "privileged": True, "permissions": ["it.iam:admin"]},
            {"id": "sales_rep", "name": "Sales Rep", "permissions": ["sales.crm:read"]},
        ],
        "groups": [
            {"id": "g-all", "name": "All", "roles": ["employee"]},
            {"id": "g-ap-clerk", "name": "AP Clerks", "roles": ["ap_clerk"]},
            {"id": "g-ap-manager", "name": "AP Managers", "roles": ["ap_manager"]},
            {"id": "g-procurement", "name": "Procurement", "roles": ["procurement"]},
            {"id": "g-iam", "name": "IAM", "roles": ["iam_admin"]},
            {"id": "g-sales", "name": "Sales", "roles": ["sales_rep"]},
        ],
        "title_baselines": {
            "Accounts Payable Clerk": ["employee", "ap_clerk"],
            "Accounts Payable Manager": ["employee", "ap_manager"],
            "Procurement Specialist": ["employee", "procurement"],
            "IAM Administrator": ["employee", "iam_admin"],
            "Sales Representative": ["employee", "sales_rep"],
        },
        "users": [
            _user(id="mgr", username="mgr", title="Accounts Payable Manager", groups=["g-all", "g-ap-manager"], manager_id=None),
            _user(id="clean", username="clean"),
            # excess: a direct grant outside the clerk baseline
            _user(id="excess", username="excess", direct_permissions=["sales.crm:export"]),
            # creep: moved from procurement to clerk and kept the procurement group
            _user(
                id="creep",
                username="creep",
                groups=["g-all", "g-ap-clerk", "g-procurement"],
                title_history=[
                    {"title": "Procurement Specialist", "start": "2022-01-10", "end": "2025-03-01"},
                    {"title": "Accounts Payable Clerk", "start": "2025-03-01", "end": None},
                ],
            ),
            # SoD: clerk who can also approve payments (maker + checker)
            _user(id="sod", username="sod", direct_permissions=["finance.payments:approve"]),
            # dormant: 120 days since login
            _user(id="dormant", username="dormant", last_login="2026-06-17"),
            # never logged in, created long ago
            _user(id="neverin", username="neverin", last_login=None, created="2026-01-01"),
            # terminated but enabled
            _user(id="termon", username="termon", status="terminated", terminated_on="2026-09-01"),
            # terminated and properly disabled
            _user(id="termoff", username="termoff", status="terminated", enabled=False, terminated_on="2026-05-01"),
            # privileged, no MFA
            _user(id="priv_nomfa", username="priv_nomfa", title="IAM Administrator", department="IT",
                  groups=["g-all", "g-iam"], mfa_enrolled=False),
            # privileged, disabled
            _user(id="priv_disabled", username="priv_disabled", title="IAM Administrator", department="IT",
                  groups=["g-all", "g-iam"], enabled=False, status="leave"),
            # ordinary user, no MFA
            _user(id="nomfa", username="nomfa", mfa_enrolled=False),
            # orphan: no manager
            _user(id="orphan", username="orphan", manager_id=None),
            # manager points at a terminated user
            _user(id="mgrgone", username="mgrgone", manager_id="termoff"),
            # service account
            _user(id="svc", username="svc-etl", account_type="service", title="Service Account", department="IT",
                  groups=[], roles=["ap_manager"], mfa_enrolled=False, manager_id=None),
            # three identical sales reps for role mining
            _user(id="s1", username="s1", title="Sales Representative", department="Sales", groups=["g-all", "g-sales"]),
            _user(id="s2", username="s2", title="Sales Representative", department="Sales", groups=["g-all", "g-sales"]),
            _user(id="s3", username="s3", title="Sales Representative", department="Sales", groups=["g-all", "g-sales"]),
        ],
    }


@pytest.fixture
def directory(raw_directory: Dict[str, Any]) -> Directory:
    return directory_from_dict(raw_directory)
