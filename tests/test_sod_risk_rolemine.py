from __future__ import annotations

import pytest

from iamtk.analyzers import dormant, least_privilege, mfa, risk, rolemine, sod
from iamtk.analyzers.sod import SodRule

RULES = [
    SodRule(id="T-001", name="create payment + approve payment", severity="critical",
            permissions=["finance.payments:create", "finance.payments:approve"]),
    SodRule(id="T-002", name="create vendor + approve payment", severity="high",
            permissions=["finance.vendors:create", "finance.payments:approve"]),
]


# ----------------------------------------------------------------- SoD -----
def test_sod_conflict_detected_with_paths(directory):
    findings, matrix = sod.analyze_with_matrix(directory, RULES)
    hits = {(f.username, f.code) for f in findings}
    assert ("sod", "T-001") in hits
    assert ("clean", "T-001") not in hits
    f = [x for x in findings if x.username == "sod" and x.code == "T-001"][0]
    assert f.severity == "critical"
    assert f.evidence["paths"]["finance.payments:approve"] == ["user:sod -> direct"]
    assert f.evidence["same_source"] is False
    assert matrix.rule_hits["T-001"] == 1
    assert matrix.rule_hits["T-002"] == 0
    assert matrix.pair_counts[("finance.payments:approve", "finance.payments:create")] == 1


def test_sod_skips_fully_offboarded_users(directory):
    user = directory.users["termoff"]
    user.direct_permissions.append("finance.payments:approve")
    findings = sod.analyze(directory, RULES)
    assert not any(f.username == "termoff" for f in findings)


def test_sod_rules_load_from_bundled_yaml():
    rules = sod.load_rules()
    ids = {r.id for r in rules}
    assert {"SOD-001", "SOD-002", "SOD-003"} <= ids
    assert all(len(r.permissions) >= 2 for r in rules)


def test_sod_rule_requires_two_permissions():
    with pytest.raises(ValueError):
        SodRule.from_dict({"id": "X", "permissions": ["only.one:perm"]})


# ---------------------------------------------------------------- risk -----
def _all_findings(directory):
    findings = []
    findings += least_privilege.analyze(directory)
    findings += dormant.analyze(directory)
    findings += mfa.analyze(directory)
    findings += sod.analyze(directory, RULES)
    return findings


def test_risk_scores_are_bounded_and_explained(directory):
    scores = risk.score_users(directory, _all_findings(directory))
    assert all(0 <= s.score <= 100 for s in scores)
    by_user = {s.username: s for s in scores}
    assert by_user["clean"].score == 0 and by_user["clean"].level == "none"
    # privileged + no MFA = 40 + 5 inherent
    assert by_user["priv_nomfa"].score == 45
    assert by_user["priv_nomfa"].level == "high"
    assert any("MFA-PRIV-MISSING" in r for r in by_user["priv_nomfa"].reasons)
    # SoD critical (20) + excess critical perm (8) + inherent (5)
    assert by_user["sod"].score == 33
    assert by_user["termon"].score == 35
    # ordering is highest first
    assert scores[0].score >= scores[-1].score


def test_risk_level_thresholds():
    assert risk.level_for(0) == "none"
    assert risk.level_for(19) == "low"
    assert risk.level_for(20) == "medium"
    assert risk.level_for(40) == "high"
    assert risk.level_for(70) == "critical"
    assert risk.level_for(100) == "critical"


def test_sod_points_are_capped(directory):
    user = directory.users["sod"]
    user.direct_permissions.append("finance.vendors:create")
    many_rules = RULES + [
        SodRule(id=f"T-{i}", name="dup", severity="critical", permissions=["finance.payments:create", "finance.payments:approve"])
        for i in range(10, 15)
    ]
    findings = sod.analyze(directory, many_rules)
    score = risk.score_user(directory, user, findings)
    sod_points = sum(int(r.split()[0]) for r in score.reasons if "SoD" in r)
    assert sod_points == risk.SOD_CAP


# ------------------------------------------------------------ role mining --
def test_jaccard():
    assert rolemine.jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert rolemine.jaccard({"a"}, {"b"}) == 0.0
    assert rolemine.jaccard({"a", "b", "c"}, {"a", "b"}) == pytest.approx(2 / 3)
    assert rolemine.jaccard(set(), set()) == 1.0


def test_role_mining_finds_sales_cluster(directory):
    suggestions = rolemine.mine_roles(directory, threshold=0.7, min_members=3)
    sales = [s for s in suggestions if set(s.members) == {"s1", "s2", "s3"}]
    assert len(sales) == 1
    s = sales[0]
    assert s.name == "mined_sales_representative"
    assert s.core_permissions == ["corp.email:use", "sales.crm:read"]
    assert s.optional_permissions == []
    assert s.closest_existing_role == "title:Sales Representative"
    assert s.closest_similarity == 1.0
    assert s.cohesion == 1.0


def test_role_mining_threshold_and_min_members(directory):
    strict = rolemine.mine_roles(directory, threshold=1.0, min_members=2)
    # identical sets only: the AP clerks (clean, dormant, neverin, nomfa, orphan, mgrgone ...) form one cluster
    clerk = [s for s in strict if "clean" in s.members][0]
    assert clerk.optional_permissions == []
    assert not any("excess" in s.members for s in strict if "clean" in s.members)
    assert rolemine.mine_roles(directory, min_members=100) == []
    with pytest.raises(ValueError):
        rolemine.mine_roles(directory, threshold=0)
