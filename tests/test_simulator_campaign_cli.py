from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from iamtk.analyzers import dormant, least_privilege, mfa, risk, sod
from iamtk.campaign import generate_campaign
from iamtk.cli import main
from iamtk.simulator import load_policy, simulate

ROOT = Path(__file__).resolve().parents[1]

POLICY = {
    "default": "deny",
    "account_state": {"deny_terminated": True, "deny_disabled": True},
    "step_up": {"require_mfa_for_sensitivity": ["critical"]},
    "deny_rules": [
        {"id": "D-1", "name": "service accounts cannot approve", "permission": "finance.*:approve",
         "when": {"account_type": "service"}},
        {"id": "D-2", "name": "IAM admin only from IT", "permission": "it.iam:admin",
         "when": {"department_not_in": ["IT"]}},
    ],
}


# ------------------------------------------------------------ simulator ----
def test_simulate_allow_with_full_path(directory):
    d = simulate(directory, "clean", "create", "finance.payments", POLICY)
    assert d.allowed and d.stage == "rbac"
    assert d.paths == ["user:clean -> group:g-ap-clerk -> role:ap_clerk"]


def test_simulate_default_deny(directory):
    d = simulate(directory, "clean", "approve", "finance.payments", POLICY)
    assert not d.allowed and d.stage == "default"


def test_simulate_account_state(directory):
    assert simulate(directory, "termon", "create", "finance.payments", POLICY).stage == "account_state"
    assert simulate(directory, "priv_disabled", "admin", "it.iam", POLICY).stage == "account_state"


def test_simulate_deny_rule_with_wildcard(directory):
    d = simulate(directory, "svc-etl", "approve", "finance.payments", POLICY)
    assert not d.allowed and d.stage == "deny_rule" and d.rule_id == "D-1"
    # same permission for a human AP manager is allowed (MFA enrolled)
    assert simulate(directory, "mgr", "approve", "finance.payments", POLICY).allowed


def test_simulate_step_up_mfa(directory):
    d = simulate(directory, "priv_nomfa", "admin", "it.iam", POLICY)
    assert not d.allowed and d.stage == "step_up"
    directory.users["priv_nomfa"].mfa_enrolled = True
    assert simulate(directory, "priv_nomfa", "admin", "it.iam", POLICY).allowed


def test_simulate_unknown_user(directory):
    assert simulate(directory, "ghost", "read", "x", POLICY).decision == "deny"


def test_bundled_policy_loads():
    policy = load_policy()
    assert policy["default"] == "deny"
    assert any(r["id"] == "DENY-001" for r in policy["deny_rules"])


# ------------------------------------------------------------- campaign ----
def test_campaign_packets_per_manager(directory, tmp_path):
    findings = least_privilege.analyze(directory) + dormant.analyze(directory) + mfa.analyze(directory)
    findings += sod.analyze(directory, sod.load_rules())
    scores = risk.score_users(directory, findings)
    packets = generate_campaign(directory, findings, scores, tmp_path, campaign_name="T1")
    names = {p.reviewer for p in packets}
    assert "mgr" in names and "_unassigned" in names
    unassigned = {p.reviewer: p for p in packets}["_unassigned"]
    rows = list(csv.DictReader(unassigned.path.open()))
    users = {r["username"] for r in rows}
    assert {"mgr", "orphan", "mgrgone", "svc-etl"} <= users  # no manager / manager terminated
    assert (tmp_path / "_index.csv").exists()

    mgr_rows = list(csv.DictReader((tmp_path / "mgr.csv").open()))
    excess_row = [r for r in mgr_rows if r["username"] == "excess" and r["permission"] == "sales.crm:export"][0]
    assert "LP-EXCESS" in excess_row["flags"]
    assert excess_row["granted_via"] == "direct"
    assert excess_row["sensitivity"] == "high"
    assert excess_row["decision"] == ""
    assert all(r["campaign"] == "T1" for r in mgr_rows)


# ------------------------------------------------------------------ CLI ----
def test_cli_audit_end_to_end_on_generated_data(tmp_path):
    data = tmp_path / "directory.json"
    gen = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_sample_data.py"), "--out", str(data), "--users", "250", "--seed", "7"],
        capture_output=True, text=True, check=True,
    )
    assert "wrote" in gen.stdout
    out = tmp_path / "reports"
    rc = main(["audit", str(data), "--out", str(out), "--sod-rules", str(ROOT / "config" / "sod_rules.yaml")])
    assert rc == 0
    report = json.loads((out / "findings.json").read_text())
    codes = report["summary"]["findings_by_code"]
    # every planted issue class is detected
    for code in ("DORM-TERMINATED", "DORM-NO-LOGIN", "MFA-PRIV-MISSING", "LP-CREEP", "LP-EXCESS",
                 "ORPHAN-NO-MANAGER", "ORPHAN-MANAGER-GONE", "SOD-001", "SOD-002"):
        assert codes.get(code, 0) > 0, code
    assert report["integrity_issues"]  # the dangling group reference
    assert (out / "report.md").exists()
    assert (out / "campaign" / "_index.csv").exists()
    assert len(report["suggested_roles"]) >= 3


def test_cli_fail_on_returns_2(tmp_path, raw_directory):
    data = tmp_path / "d.json"
    data.write_text(json.dumps(raw_directory))
    rc = main(["audit", str(data), "--out", str(tmp_path / "r"), "--fail-on", "critical", "--no-rolemine"])
    assert rc == 2


def test_cli_simulate_and_rolemine(tmp_path, raw_directory, capsys):
    data = tmp_path / "d.json"
    data.write_text(json.dumps(raw_directory))
    rc = main(["simulate", str(data), "--user", "clean", "--action", "create", "--resource", "finance.payments", "--json"])
    assert rc == 0
    decision = json.loads(capsys.readouterr().out)
    assert decision["decision"] == "allow"

    rc = main(["simulate", str(data), "--user", "clean", "--action", "approve", "--resource", "finance.payments"])
    assert rc == 1
    assert "DENY" in capsys.readouterr().out

    rc = main(["rolemine", str(data), "--json", "--min-members", "3"])
    assert rc == 0
    suggestions = json.loads(capsys.readouterr().out)
    assert any(s["suggested_name"] == "mined_sales_representative" for s in suggestions)

    rc = main(["explain", str(data), "--user", "creep"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "LP-CREEP" in out and "EXCESS" in out
