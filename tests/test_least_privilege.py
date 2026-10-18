from __future__ import annotations

from iamtk.analyzers import least_privilege


def _by_user(findings):
    out = {}
    for f in findings:
        out.setdefault(f.username, []).append(f)
    return out


def test_clean_user_has_no_findings(directory):
    assert least_privilege.analyze_user(directory, directory.users["clean"]) == []


def test_excess_permission_is_flagged_with_path(directory):
    findings = least_privilege.analyze_user(directory, directory.users["excess"])
    assert [f.code for f in findings] == ["LP-EXCESS"]
    f = findings[0]
    assert f.evidence["excess_permissions"] == ["sales.crm:export"]
    assert f.evidence["paths"]["sales.crm:export"] == ["user:excess -> direct"]
    assert f.severity == "high"  # sales.crm:export is high sensitivity


def test_privilege_creep_attributed_to_former_title(directory):
    findings = least_privilege.analyze_user(directory, directory.users["creep"])
    codes = {f.code for f in findings}
    assert codes == {"LP-CREEP"}  # everything extra is explained by the old title
    creep = findings[0]
    assert creep.evidence["creep_permissions"] == {"finance.vendors:create": ["Procurement Specialist"]}
    assert creep.evidence["former_titles"] == ["Procurement Specialist"]
    assert "group:g-procurement" in creep.evidence["paths"]["finance.vendors:create"][0]


def test_unknown_title_reports_missing_baseline(directory):
    user = directory.users["clean"]
    user.title = "Wizard"
    findings = least_privilege.analyze_user(directory, user)
    assert [f.code for f in findings] == ["LP-NO-BASELINE"]


def test_service_accounts_are_skipped(directory):
    by_user = _by_user(least_privilege.analyze(directory))
    assert "svc-etl" not in by_user
    assert set(by_user) >= {"excess", "creep", "sod"}
