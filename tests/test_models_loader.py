from __future__ import annotations

import json
from datetime import date

import pytest

from iamtk.loader import DirectoryFormatError, directory_from_dict, load_directory


def test_effective_permissions_resolve_through_groups_and_roles(directory):
    clean = directory.users["clean"]
    assert directory.effective_permissions(clean) == {
        "corp.email:use",
        "finance.vendors:read",
        "finance.payments:create",
    }


def test_grant_paths_record_provenance(directory):
    sod = directory.users["sod"]
    paths = {g.permission: g.path_str() for g in directory.grants_for(sod)}
    assert paths["finance.payments:approve"] == "user:sod -> direct"
    assert paths["finance.payments:create"] == "user:sod -> group:g-ap-clerk -> role:ap_clerk"


def test_baseline_for_title(directory):
    assert directory.baseline_for_title("Accounts Payable Clerk") == {
        "corp.email:use",
        "finance.vendors:read",
        "finance.payments:create",
    }
    assert directory.baseline_for_title("Unknown Title") == set()


def test_privileged_user_detection(directory):
    assert directory.is_privileged_user(directory.users["priv_nomfa"])  # privileged role
    assert directory.is_privileged_user(directory.users["sod"])  # critical permission
    assert not directory.is_privileged_user(directory.users["clean"])


def test_user_lookup_by_name_or_email(directory):
    assert directory.user_by_name("CLEAN").id == "clean"
    assert directory.user_by_name("clean@example.com").id == "clean"
    assert directory.user_by_name("nobody") is None


def test_past_titles_excludes_current(directory):
    assert directory.users["creep"].past_titles == ["Procurement Specialist"]
    assert directory.users["clean"].past_titles == []


def test_loader_reads_as_of_from_meta_and_override(raw_directory, tmp_path):
    path = tmp_path / "dir.json"
    path.write_text(json.dumps(raw_directory))
    assert load_directory(path).as_of == date(2026, 10, 15)
    assert load_directory(path, as_of=date(2027, 1, 1)).as_of == date(2027, 1, 1)


def test_loader_rejects_missing_sections_and_duplicates(raw_directory):
    bad = dict(raw_directory)
    del bad["roles"]
    with pytest.raises(DirectoryFormatError):
        directory_from_dict(bad)
    dup = dict(raw_directory)
    dup["users"] = raw_directory["users"] + [raw_directory["users"][0]]
    with pytest.raises(DirectoryFormatError):
        directory_from_dict(dup)


def test_unknown_references_are_reported(raw_directory):
    raw_directory["users"][1]["groups"].append("g-does-not-exist")
    directory = directory_from_dict(raw_directory)
    issues = directory.unknown_references()
    assert any("g-does-not-exist" in i for i in issues)
