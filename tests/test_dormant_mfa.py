from __future__ import annotations

from iamtk.analyzers import dormant, mfa


def _codes(findings, username):
    return sorted(f.code for f in findings if f.username == username)


def test_dormant_threshold(directory):
    findings = dormant.analyze(directory, dormant_days=90)
    assert _codes(findings, "dormant") == ["DORM-NO-LOGIN"]
    assert _codes(findings, "clean") == []
    # raise the threshold and the 120-day gap is no longer dormant
    assert _codes(dormant.analyze(directory, dormant_days=180), "dormant") == []


def test_never_logged_in(directory):
    findings = dormant.analyze(directory)
    f = [x for x in findings if x.username == "neverin"][0]
    assert f.code == "DORM-NO-LOGIN"
    assert f.evidence["last_login"] is None
    assert f.evidence["days_idle"] > 90


def test_terminated_but_enabled_vs_properly_disabled(directory):
    findings = dormant.analyze(directory)
    assert _codes(findings, "termon") == ["DORM-TERMINATED"]
    assert _codes(findings, "termoff") == []
    f = [x for x in findings if x.username == "termon"][0]
    assert f.evidence["days_since_termination"] == 44


def test_terminated_privileged_is_critical(directory):
    user = directory.users["termon"]
    user.direct_permissions.append("it.iam:admin")
    f = [x for x in dormant.analyze_user(directory, user) if x.code == "DORM-TERMINATED"][0]
    assert f.severity == "critical"


def test_disabled_privileged_account_flagged(directory):
    findings = dormant.analyze(directory)
    assert "DORM-DISABLED-ACCESS" in _codes(findings, "priv_disabled")
    assert "DORM-NO-LOGIN" not in _codes(findings, "priv_disabled")  # disabled accounts are not "dormant"


def test_orphans(directory):
    findings = dormant.analyze(directory)
    assert _codes(findings, "orphan") == ["ORPHAN-NO-MANAGER"]
    assert _codes(findings, "mgrgone") == ["ORPHAN-MANAGER-GONE"]
    assert "ORPHAN-NO-MANAGER" in _codes(findings, "svc-etl")


def test_mfa_privileged_without_mfa_is_critical(directory):
    findings, summary = mfa.analyze_with_summary(directory)
    assert _codes(findings, "priv_nomfa") == ["MFA-PRIV-MISSING"]
    assert [f.severity for f in findings if f.username == "priv_nomfa"] == ["critical"]
    assert _codes(findings, "nomfa") == ["MFA-MISSING"]
    assert _codes(findings, "clean") == []
    # service accounts and disabled/terminated users are not nagged
    assert _codes(findings, "svc-etl") == []
    assert _codes(findings, "termon") == []
    assert _codes(findings, "priv_disabled") == []


def test_mfa_summary_counts(directory):
    _, summary = mfa.analyze_with_summary(directory)
    assert summary.service_accounts == 1
    assert summary.humans_total == 14  # active, enabled humans
    assert summary.humans_enrolled == 12
    # mgr, sod, creep (vendors:create is high), excess (crm:export is high), priv_nomfa
    assert summary.privileged_total == 5
    assert summary.privileged_enrolled == 4
    assert summary.unenrolled_by_department == {"Finance": 1, "IT": 1}
