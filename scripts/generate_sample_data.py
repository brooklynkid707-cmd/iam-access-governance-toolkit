#!/usr/bin/env python3
"""Generate a synthetic identity-directory export with planted governance issues.

Everything here is fake: names are assembled from small word lists, e-mail
addresses use ``example.com`` and no real organisation is modelled.  The
generator is seeded so the same ``--seed`` always produces the same file,
which keeps the README output and the test fixtures reproducible.

Planted issues (so the analyzers have something to find):

* terminated-but-enabled accounts (a couple of them privileged)
* dormant accounts (no login > 90 days) and never-logged-in accounts
* privileged users without MFA
* privilege creep: users who changed title but kept the old group
* separation-of-duties conflicts (vendor+payment, payroll run+approve,
  deploy+approve, IAM admin+payment approval, break-glass group)
* orphaned accounts (no manager / manager terminated)
* a few direct permission grants outside the title baseline
* service accounts, some with no owner and no recent activity
* one dangling group reference to exercise the integrity check

Usage::

    python scripts/generate_sample_data.py --out data/directory.json --users 250 --seed 20261017
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

AS_OF = date(2026, 10, 15)

FIRST_NAMES = [
    "Avery", "Blake", "Casey", "Dana", "Elliot", "Finley", "Gray", "Harper", "Indigo", "Jules",
    "Kai", "Logan", "Morgan", "Noel", "Oakley", "Parker", "Quinn", "Reese", "Sawyer", "Tatum",
    "Uma", "Val", "Wren", "Xen", "Yael", "Zion", "Adrian", "Bea", "Cruz", "Devon",
    "Ezra", "Flor", "Gale", "Hollis", "Ira", "Jem", "Kit", "Lane", "Mika", "Nico",
]
LAST_NAMES = [
    "Abbott", "Barlow", "Calder", "Dunmore", "Ellery", "Fairweather", "Garnett", "Holloway",
    "Ingram", "Jarvis", "Kemp", "Lockwood", "Marchetti", "Navarro", "Okafor", "Pemberton",
    "Quigley", "Rasmussen", "Sato", "Thornbury", "Underhill", "Vance", "Whitlock", "Xiang",
    "Yamada", "Zelinsky", "Ashdown", "Brennan", "Castellano", "Delacroix",
]

# ----------------------------------------------------------------------------
# Permission catalogue: id -> (sensitivity, description)
PERMISSIONS: Dict[str, tuple[str, str]] = {
    "corp.intranet:read": ("low", "Read the intranet"),
    "corp.email:use": ("low", "Use corporate e-mail"),
    "corp.directory:read": ("low", "Browse the employee directory"),
    "finance.vendors:read": ("low", "View vendor master data"),
    "finance.vendors:create": ("high", "Create vendor records"),
    "finance.vendors:update": ("medium", "Edit vendor records"),
    "finance.vendors:approve": ("high", "Approve new vendors"),
    "finance.payments:read": ("low", "View payment runs"),
    "finance.payments:create": ("medium", "Create payment requests"),
    "finance.payments:approve": ("critical", "Approve outgoing payments"),
    "finance.ledger:read": ("low", "Read the general ledger"),
    "finance.ledger:post": ("high", "Post journal entries"),
    "hr.employees:read": ("medium", "Read employee records (PII)"),
    "hr.employees:update": ("high", "Edit employee master data"),
    "hr.employees:terminate": ("high", "Process terminations"),
    "hr.payroll:read": ("medium", "View payroll"),
    "hr.payroll:run": ("critical", "Execute payroll"),
    "hr.payroll:approve": ("high", "Approve payroll run"),
    "it.servers:read": ("low", "View server inventory"),
    "it.servers:admin": ("critical", "Administer servers (root/local admin)"),
    "it.iam:read": ("low", "View identities and groups"),
    "it.iam:admin": ("critical", "Create accounts, assign roles and groups"),
    "it.backups:read": ("low", "View backup jobs"),
    "it.backups:restore": ("high", "Restore from backup"),
    "it.backups:delete": ("critical", "Delete backup sets"),
    "eng.repo:read": ("low", "Read source repositories"),
    "eng.repo:write": ("medium", "Push to source repositories"),
    "eng.repo:merge": ("medium", "Merge to protected branches"),
    "eng.prod:deploy": ("high", "Deploy to production"),
    "eng.prod:approve_deploy": ("high", "Approve production deployments"),
    "sales.crm:read": ("low", "View CRM"),
    "sales.crm:write": ("medium", "Edit CRM records"),
    "sales.crm:export": ("high", "Bulk-export CRM data"),
    "support.tickets:read": ("low", "View support tickets"),
    "support.tickets:write": ("low", "Update support tickets"),
    "support.tickets:admin": ("medium", "Administer the ticketing system"),
}

ROLES: Dict[str, Dict[str, Any]] = {
    "employee": {"name": "Employee (baseline)", "permissions": ["corp.intranet:read", "corp.email:use", "corp.directory:read"]},
    "ap_clerk": {"name": "AP Clerk", "permissions": ["finance.vendors:read", "finance.payments:create", "finance.payments:read", "finance.ledger:read"]},
    "ap_manager": {"name": "AP Manager", "permissions": ["finance.vendors:read", "finance.vendors:approve", "finance.payments:read", "finance.payments:approve", "finance.ledger:read"]},
    "procurement_specialist": {"name": "Procurement Specialist", "permissions": ["finance.vendors:read", "finance.vendors:create", "finance.vendors:update"]},
    "accountant": {"name": "Staff Accountant", "permissions": ["finance.ledger:read", "finance.ledger:post", "finance.payments:read"]},
    "finance_director": {"name": "Finance Director", "permissions": ["finance.vendors:read", "finance.vendors:approve", "finance.payments:read", "finance.payments:approve", "finance.ledger:read"]},
    "hr_generalist": {"name": "HR Generalist", "permissions": ["hr.employees:read", "hr.employees:update"]},
    "hr_manager": {"name": "HR Manager", "permissions": ["hr.employees:read", "hr.employees:update", "hr.employees:terminate", "hr.payroll:read", "hr.payroll:approve"]},
    "payroll_admin": {"name": "Payroll Administrator", "permissions": ["hr.employees:read", "hr.payroll:read", "hr.payroll:run"]},
    "sysadmin": {"name": "Systems Administrator", "privileged": True, "permissions": ["it.servers:read", "it.servers:admin", "it.backups:read", "it.backups:restore", "it.iam:read"]},
    "iam_admin": {"name": "IAM Administrator", "privileged": True, "permissions": ["it.iam:read", "it.iam:admin"]},
    "backup_operator": {"name": "Backup Operator", "privileged": True, "permissions": ["it.backups:read", "it.backups:restore", "it.servers:read"]},
    "helpdesk": {"name": "Help Desk", "permissions": ["support.tickets:read", "support.tickets:write", "it.iam:read", "it.servers:read"]},
    "it_manager": {"name": "IT Manager", "permissions": ["it.servers:read", "it.iam:read", "it.backups:read", "support.tickets:read"]},
    "software_engineer": {"name": "Software Engineer", "permissions": ["eng.repo:read", "eng.repo:write", "support.tickets:read"]},
    "senior_engineer": {"name": "Senior Engineer", "permissions": ["eng.repo:read", "eng.repo:write", "eng.repo:merge", "eng.prod:deploy", "support.tickets:read"]},
    "release_manager": {"name": "Release Manager", "permissions": ["eng.repo:read", "eng.prod:deploy", "eng.prod:approve_deploy"]},
    "eng_manager": {"name": "Engineering Manager", "permissions": ["eng.repo:read", "eng.repo:merge", "eng.prod:approve_deploy", "support.tickets:read"]},
    "sales_rep": {"name": "Sales Representative", "permissions": ["sales.crm:read", "sales.crm:write"]},
    "sales_manager": {"name": "Sales Manager", "permissions": ["sales.crm:read", "sales.crm:write", "sales.crm:export"]},
    "support_agent": {"name": "Support Agent", "permissions": ["support.tickets:read", "support.tickets:write", "sales.crm:read"]},
    "support_manager": {"name": "Support Manager", "permissions": ["support.tickets:read", "support.tickets:write", "support.tickets:admin", "sales.crm:read"]},
    "executive": {"name": "Executive", "permissions": ["finance.ledger:read", "finance.payments:read", "hr.employees:read", "sales.crm:read"]},
}

# title -> (department, baseline roles, weight for random sampling)
TITLES: Dict[str, tuple[str, List[str], int]] = {
    "Accounts Payable Clerk": ("Finance", ["employee", "ap_clerk"], 8),
    "Accounts Payable Manager": ("Finance", ["employee", "ap_manager"], 2),
    "Procurement Specialist": ("Finance", ["employee", "procurement_specialist"], 5),
    "Staff Accountant": ("Finance", ["employee", "accountant"], 6),
    "Finance Director": ("Finance", ["employee", "finance_director"], 0),
    "HR Generalist": ("HR", ["employee", "hr_generalist"], 6),
    "HR Manager": ("HR", ["employee", "hr_manager"], 0),
    "Payroll Administrator": ("HR", ["employee", "payroll_admin"], 3),
    "Systems Administrator": ("IT", ["employee", "sysadmin"], 7),
    "IAM Administrator": ("IT", ["employee", "iam_admin"], 3),
    "Backup Operator": ("IT", ["employee", "backup_operator"], 3),
    "Help Desk Technician": ("IT", ["employee", "helpdesk"], 10),
    "IT Manager": ("IT", ["employee", "it_manager"], 0),
    "Software Engineer": ("Engineering", ["employee", "software_engineer"], 40),
    "Senior Software Engineer": ("Engineering", ["employee", "senior_engineer"], 18),
    "Release Manager": ("Engineering", ["employee", "release_manager"], 3),
    "Engineering Manager": ("Engineering", ["employee", "eng_manager"], 0),
    "Sales Representative": ("Sales", ["employee", "sales_rep"], 38),
    "Sales Manager": ("Sales", ["employee", "sales_manager"], 0),
    "Support Agent": ("Support", ["employee", "support_agent"], 30),
    "Support Manager": ("Support", ["employee", "support_manager"], 0),
    "Chief Executive Officer": ("Executive", ["employee", "executive"], 0),
}

# Department leadership: (title, how many)
LEADERSHIP = {
    "Finance": [("Finance Director", 1), ("Accounts Payable Manager", 1)],
    "HR": [("HR Manager", 1)],
    "IT": [("IT Manager", 2)],
    "Engineering": [("Engineering Manager", 4)],
    "Sales": [("Sales Manager", 3)],
    "Support": [("Support Manager", 2)],
}


def slug(title: str) -> str:
    return title.lower().replace(" ", "-")


class Generator:
    def __init__(self, seed: int, target_users: int) -> None:
        self.rng = random.Random(seed)
        self.target_users = target_users
        self.users: List[Dict[str, Any]] = []
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.used_usernames: set[str] = set()
        self.next_id = 1
        self.notes: List[str] = []

    # ------------------------------------------------------------- helpers
    def _name(self) -> tuple[str, str, str]:
        while True:
            first = self.rng.choice(FIRST_NAMES)
            last = self.rng.choice(LAST_NAMES)
            username = (first[0] + last).lower()
            if username not in self.used_usernames:
                self.used_usernames.add(username)
                return first, last, username
            # collision: add a digit suffix
            for n in range(2, 10):
                cand = f"{username}{n}"
                if cand not in self.used_usernames:
                    self.used_usernames.add(cand)
                    return first, last, cand

    def _date_before(self, min_days: int, max_days: int) -> date:
        return AS_OF - timedelta(days=self.rng.randint(min_days, max_days))

    def _group_for_title(self, title: str) -> str:
        gid = f"g-{slug(title)}"
        if gid not in self.groups:
            _, roles, _ = TITLES[title]
            self.groups[gid] = {
                "id": gid,
                "name": f"{title}s",
                "roles": [r for r in roles if r != "employee"],
                "permissions": [],
                "description": f"Auto-provisioned group for the '{title}' job title",
            }
        return gid

    def _make_user(self, title: str, manager_id: Optional[str], account_type: str = "human") -> Dict[str, Any]:
        first, last, username = self._name()
        department, _, _ = TITLES[title]
        created = self._date_before(120, 2400)
        uid = f"u{self.next_id:04d}"
        self.next_id += 1
        user = {
            "id": uid,
            "username": username,
            "display_name": f"{first} {last}",
            "email": f"{username}@example.com",
            "department": department,
            "title": title,
            "account_type": account_type,
            "status": "active",
            "enabled": True,
            "mfa_enrolled": self.rng.random() < 0.9,
            "manager_id": manager_id,
            "created": created.isoformat(),
            "last_login": self._date_before(0, 21).isoformat(),
            "groups": ["g-all-employees", self._group_for_title(title)],
            "roles": [],
            "direct_permissions": [],
            "title_history": [{"title": title, "start": created.isoformat(), "end": None}],
        }
        self.users.append(user)
        return user

    # ------------------------------------------------------------ building
    def build(self) -> Dict[str, Any]:
        self.groups["g-all-employees"] = {
            "id": "g-all-employees",
            "name": "All Employees",
            "roles": ["employee"],
            "permissions": [],
            "description": "Every active identity",
        }
        self.groups["g-breakglass"] = {
            "id": "g-breakglass",
            "name": "Break-glass Infrastructure",
            "roles": [],
            "permissions": ["it.servers:admin", "it.backups:delete"],
            "description": "Emergency access; membership should be empty outside incidents",
        }

        ceo = self._make_user("Chief Executive Officer", None)
        managers_by_dept: Dict[str, List[Dict[str, Any]]] = {}
        for dept, leaders in LEADERSHIP.items():
            for title, count in leaders:
                for _ in range(count):
                    mgr = self._make_user(title, ceo["id"])
                    managers_by_dept.setdefault(dept, []).append(mgr)

        # Rank and file --------------------------------------------------------
        weighted = [(t, w) for t, (_, _, w) in TITLES.items() if w > 0]
        titles, weights = zip(*weighted)
        while len(self.users) < self.target_users - 10:  # leave room for service accounts
            title = self.rng.choices(titles, weights=weights, k=1)[0]
            dept = TITLES[title][0]
            manager = self.rng.choice(managers_by_dept[dept])
            self._make_user(title, manager["id"])

        # Service accounts -----------------------------------------------------
        it_managers = managers_by_dept["IT"]
        svc_specs = [
            ("svc-backup", ["backup_operator"], it_managers[0]["id"], 2),
            ("svc-ci-deploy", ["release_manager"], managers_by_dept["Engineering"][0]["id"], 1),
            ("svc-hr-sync", ["hr_generalist"], managers_by_dept["HR"][0]["id"], 3),
            ("svc-crm-etl", ["sales_manager"], None, 400),          # orphan + dormant
            ("svc-monitoring", ["sysadmin"], it_managers[1]["id"], 0),
            ("svc-legacy-erp", ["ap_manager"], None, 300),          # orphan + dormant + no MFA
            ("svc-ldap-bind", ["iam_admin"], it_managers[0]["id"], 1),
            ("svc-ticket-bot", ["support_agent"], managers_by_dept["Support"][0]["id"], 0),
            ("svc-payroll-export", ["payroll_admin"], managers_by_dept["HR"][0]["id"], 5),
            ("svc-report-gen", ["accountant"], managers_by_dept["Finance"][0]["id"], 2),
        ]
        for name, roles, manager_id, days_idle in svc_specs:
            uid = f"u{self.next_id:04d}"
            self.next_id += 1
            self.used_usernames.add(name)
            self.users.append(
                {
                    "id": uid,
                    "username": name,
                    "display_name": name,
                    "email": f"{name}@example.com",
                    "department": "IT",
                    "title": "Service Account",
                    "account_type": "service",
                    "status": "active",
                    "enabled": True,
                    "mfa_enrolled": False,
                    "manager_id": manager_id,
                    "created": self._date_before(400, 2000).isoformat(),
                    "last_login": (AS_OF - timedelta(days=days_idle)).isoformat(),
                    "groups": [],
                    "roles": roles,
                    "direct_permissions": [],
                    "title_history": [],
                }
            )

        self._plant_issues()
        self.users.sort(key=lambda u: u["id"])

        return {
            "meta": {
                "source": "synthetic-directory-export",
                "exported_at": AS_OF.isoformat(),
                "generator": "scripts/generate_sample_data.py",
                "planted_issues": self.notes,
            },
            "permissions": [
                {"id": pid, "sensitivity": sens, "description": desc} for pid, (sens, desc) in PERMISSIONS.items()
            ],
            "roles": [
                {"id": rid, "name": r["name"], "privileged": r.get("privileged", False), "permissions": r["permissions"]}
                for rid, r in ROLES.items()
            ],
            "groups": list(self.groups.values()),
            "title_baselines": {t: roles for t, (_, roles, _) in TITLES.items()},
            "users": self.users,
        }

    # ------------------------------------------------------------ planting
    def _pick(self, predicate, n: int, exclude: set[str]) -> List[Dict[str, Any]]:
        pool = [u for u in self.users if u["account_type"] == "human" and u["id"] not in exclude and predicate(u)]
        self.rng.shuffle(pool)
        chosen = pool[:n]
        exclude.update(u["id"] for u in chosen)
        return chosen

    def _plant_issues(self) -> None:
        used: set[str] = set()
        is_ic = lambda u: u["title"] not in {t for leaders in LEADERSHIP.values() for t, _ in leaders} and u["title"] != "Chief Executive Officer"  # noqa: E731
        privileged_titles = {"Systems Administrator", "IAM Administrator", "Backup Operator", "Senior Software Engineer",
                             "Accounts Payable Manager", "Payroll Administrator", "Release Manager"}

        # 4. Privilege creep: changed title but kept old group (12)
        moves = [
            ("Accounts Payable Clerk", "Staff Accountant"),
            ("Procurement Specialist", "Accounts Payable Clerk"),
            ("Help Desk Technician", "Systems Administrator"),
            ("Systems Administrator", "Software Engineer"),
            ("Software Engineer", "Senior Software Engineer"),
            ("Sales Representative", "Support Agent"),
            ("Support Agent", "Sales Representative"),
            ("HR Generalist", "Payroll Administrator"),
            ("Backup Operator", "Help Desk Technician"),
            ("IAM Administrator", "Help Desk Technician"),
            ("Senior Software Engineer", "Release Manager"),
            ("Accounts Payable Clerk", "Sales Representative"),
        ]
        for old_title, new_title in moves:
            picked = self._pick(lambda u, t=new_title: u["title"] == t, 1, used)
            if not picked:
                continue
            u = picked[0]
            changed = self._date_before(60, 700)
            start_old = changed - timedelta(days=self.rng.randint(300, 1200))
            u["title_history"] = [
                {"title": old_title, "start": start_old.isoformat(), "end": changed.isoformat()},
                {"title": new_title, "start": changed.isoformat(), "end": None},
            ]
            u["created"] = min(date.fromisoformat(u["created"]), start_old).isoformat()
            old_group = self._group_for_title(old_title)
            if old_group not in u["groups"]:
                u["groups"].append(old_group)
            u["department"] = TITLES[new_title][0]
            self.notes.append(f"{u['username']}: moved {old_title} -> {new_title} on {changed}, kept {old_group}")

        # 5. Separation-of-duties conflicts
        # 5a. AP clerk given payment approval directly (maker + checker)
        for u in self._pick(lambda u: u["title"] == "Accounts Payable Clerk", 2, used):
            u["direct_permissions"].append("finance.payments:approve")
            self.notes.append(f"{u['username']}: AP clerk with direct finance.payments:approve (SoD-002)")
        # 5b. Procurement specialist added to AP manager group (vendor create + payment approve)
        for u in self._pick(lambda u: u["title"] == "Procurement Specialist", 2, used):
            u["groups"].append("g-accounts-payable-manager")
            self.notes.append(f"{u['username']}: procurement specialist in AP manager group (SoD-001)")
        # 5c. Payroll admin who also holds the HR manager role directly
        for u in self._pick(lambda u: u["title"] == "Payroll Administrator", 1, used):
            u["roles"].append("hr_manager")
            self.notes.append(f"{u['username']}: payroll admin with hr_manager role (SoD-003/004)")
        # 5d. Senior engineer who can approve their own deploys
        for u in self._pick(lambda u: u["title"] == "Senior Software Engineer", 2, used):
            u["direct_permissions"].append("eng.prod:approve_deploy")
            self.notes.append(f"{u['username']}: senior engineer with direct approve_deploy (SoD-005)")
        # 5e. IAM admin moonlighting as payment approver
        for u in self._pick(lambda u: u["title"] == "IAM Administrator", 1, used):
            u["groups"].append("g-accounts-payable-manager")
            self.notes.append(f"{u['username']}: IAM admin in AP manager group (SoD-006)")
        # 5f. Break-glass group that was never emptied after an incident
        for u in self._pick(lambda u: u["title"] == "Systems Administrator", 3, used):
            u["groups"].append("g-breakglass")
            self.notes.append(f"{u['username']}: still in g-breakglass (SoD-008)")

        # 1. Terminated but still enabled (2 privileged, 6 ordinary)
        for u in self._pick(lambda u: u["title"] in privileged_titles and is_ic(u), 2, used) + \
                 self._pick(lambda u: u["title"] not in privileged_titles and is_ic(u), 6, used):
            term = self._date_before(5, 120)
            u["status"] = "terminated"
            u["terminated_on"] = term.isoformat()
            u["last_login"] = (term - timedelta(days=self.rng.randint(0, 3))).isoformat()
            u["enabled"] = True
            self.notes.append(f"{u['username']}: terminated {term} but account still enabled")

        # 1b. Properly offboarded (disabled) - should NOT be flagged as terminated-enabled
        for u in self._pick(is_ic, 6, used):
            term = self._date_before(30, 400)
            u["status"] = "terminated"
            u["terminated_on"] = term.isoformat()
            u["enabled"] = False
            u["last_login"] = (term - timedelta(days=1)).isoformat()

        # 1c. Disabled but still holding privileged entitlements
        for u in self._pick(lambda u: u["title"] in {"Systems Administrator", "IAM Administrator"} and is_ic(u), 2, used):
            u["enabled"] = False
            u["status"] = "leave"
            self.notes.append(f"{u['username']}: disabled (leave) but privileged groups never removed")

        # 2. Dormant: no login > 90 days (18 users), plus never-logged-in (4)
        for u in self._pick(is_ic, 18, used):
            u["last_login"] = self._date_before(95, 420).isoformat()
            self.notes.append(f"{u['username']}: dormant, last login {u['last_login']}")
        for u in self._pick(is_ic, 4, used):
            u["last_login"] = None
            u["created"] = self._date_before(100, 300).isoformat()
            self.notes.append(f"{u['username']}: never logged in")

        # 3. Privileged users without MFA (10)
        for u in self._pick(lambda u: u["title"] in privileged_titles and u["mfa_enrolled"], 10, used):
            u["mfa_enrolled"] = False
            self.notes.append(f"{u['username']}: privileged ({u['title']}) without MFA")

        # 6. Orphans
        for u in self._pick(is_ic, 4, used):
            u["manager_id"] = None
            self.notes.append(f"{u['username']}: no manager recorded")
        # 6b. Manager terminated but reports not re-assigned
        victim_mgr = self._pick(lambda u: u["title"] == "Engineering Manager", 1, used)[0]
        term = self._date_before(10, 60)
        victim_mgr.update({"status": "terminated", "terminated_on": term.isoformat(), "enabled": False,
                           "last_login": (term - timedelta(days=1)).isoformat()})
        self.notes.append(f"{victim_mgr['username']}: engineering manager terminated; direct reports now orphaned")

        # 7. Assorted direct grants outside baseline (excess, not creep)
        extras = [
            ("Sales Representative", "sales.crm:export"),
            ("Sales Representative", "sales.crm:export"),
            ("Support Agent", "hr.employees:read"),
            ("Software Engineer", "eng.prod:deploy"),
            ("Software Engineer", "it.servers:admin"),
            ("Help Desk Technician", "it.iam:admin"),
            ("Staff Accountant", "finance.vendors:update"),
            ("Support Agent", "sales.crm:write"),
        ]
        for title, perm in extras:
            picked = self._pick(lambda u, t=title: u["title"] == t, 1, used)
            if picked:
                picked[0]["direct_permissions"].append(perm)
                self.notes.append(f"{picked[0]['username']}: direct grant {perm} outside '{title}' baseline")

        # 8. One dangling reference to exercise the integrity check
        u = self._pick(is_ic, 1, used)[0]
        u["groups"].append("g-legacy-fileshare")
        self.notes.append(f"{u['username']}: member of non-existent group g-legacy-fileshare")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("data/directory.json"))
    parser.add_argument("--users", type=int, default=250, help="approximate number of users")
    parser.add_argument("--seed", type=int, default=20261017)
    args = parser.parse_args()

    export = Generator(args.seed, args.users).build()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(export, indent=2), encoding="utf-8")
    print(f"wrote {args.out}: {len(export['users'])} users, {len(export['groups'])} groups, "
          f"{len(export['roles'])} roles, {len(export['permissions'])} permissions, "
          f"{len(export['meta']['planted_issues'])} planted issues (seed {args.seed})")


if __name__ == "__main__":
    main()
