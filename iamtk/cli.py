"""Command-line interface for the IAM Access Governance Toolkit.

    python -m iamtk audit data/directory.json --out reports/
    python -m iamtk simulate data/directory.json --user jdoe --action approve --resource finance.payments
    python -m iamtk rolemine data/directory.json --threshold 0.7 --min-members 3
    python -m iamtk explain data/directory.json --user jdoe
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import List, Optional

from . import __version__
from .analyzers import dormant, least_privilege, mfa, risk, rolemine, sod
from .campaign import generate_campaign
from .findings import Finding
from .loader import load_directory
from .report import AuditResult, render_table
from .simulator import load_policy, simulate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iamtk",
        description="Audit an identity directory export for least-privilege, dormant-account, MFA and SoD issues.",
    )
    parser.add_argument("--version", action="version", version=f"iamtk {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # audit -------------------------------------------------------------------
    p_audit = sub.add_parser("audit", help="run every analyzer and write JSON/Markdown/CSV reports")
    p_audit.add_argument("directory", type=Path, help="directory export (JSON)")
    p_audit.add_argument("--out", type=Path, default=Path("reports"), help="output folder (default: reports/)")
    p_audit.add_argument("--sod-rules", type=Path, default=None, help="SoD rules YAML (default: config/sod_rules.yaml)")
    p_audit.add_argument("--dormant-days", type=int, default=dormant.DEFAULT_DORMANT_DAYS, help="dormancy threshold in days")
    p_audit.add_argument("--as-of", type=date.fromisoformat, default=None, help="override snapshot date (YYYY-MM-DD)")
    p_audit.add_argument("--top", type=int, default=10, help="rows in the console risk table")
    p_audit.add_argument("--campaign-name", default="Q4-access-review", help="campaign label written into packets")
    p_audit.add_argument("--no-campaign", action="store_true", help="skip CSV review packets")
    p_audit.add_argument("--no-rolemine", action="store_true", help="skip role mining")
    p_audit.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None,
                         help="exit 2 if any finding at or above this severity exists (CI mode)")

    # simulate ----------------------------------------------------------------
    p_sim = sub.add_parser("simulate", help="evaluate whether a user may perform an action on a resource")
    p_sim.add_argument("directory", type=Path)
    p_sim.add_argument("--user", required=True, help="username, user id or email")
    p_sim.add_argument("--action", required=True, help="e.g. approve")
    p_sim.add_argument("--resource", required=True, help="e.g. finance.payments")
    p_sim.add_argument("--policy", type=Path, default=None, help="policy YAML (default: config/policy.yaml)")
    p_sim.add_argument("--json", action="store_true", help="print the decision as JSON")

    # rolemine ----------------------------------------------------------------
    p_rm = sub.add_parser("rolemine", help="suggest roles from clustered permission sets")
    p_rm.add_argument("directory", type=Path)
    p_rm.add_argument("--threshold", type=float, default=0.7, help="Jaccard similarity threshold (default 0.7)")
    p_rm.add_argument("--min-members", type=int, default=3, help="minimum users per suggested role")
    p_rm.add_argument("--json", action="store_true", help="print suggestions as JSON")

    # explain -----------------------------------------------------------------
    p_ex = sub.add_parser("explain", help="show one user's effective access, grant paths and findings")
    p_ex.add_argument("directory", type=Path)
    p_ex.add_argument("--user", required=True)
    p_ex.add_argument("--sod-rules", type=Path, default=None)
    p_ex.add_argument("--dormant-days", type=int, default=dormant.DEFAULT_DORMANT_DAYS)
    return parser


# ----------------------------------------------------------------------------
def run_audit(args: argparse.Namespace) -> int:
    directory = load_directory(args.directory, as_of=args.as_of)
    integrity = directory.unknown_references()

    findings: List[Finding] = []
    findings += least_privilege.analyze(directory)
    findings += dormant.analyze(directory, dormant_days=args.dormant_days)
    mfa_findings, mfa_summary = mfa.analyze_with_summary(directory)
    findings += mfa_findings
    rules = sod.load_rules(args.sod_rules)
    sod_findings, matrix = sod.analyze_with_matrix(directory, rules)
    findings += sod_findings

    scores = risk.score_users(directory, findings)
    suggested = [] if args.no_rolemine else rolemine.mine_roles(directory)

    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    packets = []
    if not args.no_campaign:
        packets = generate_campaign(directory, findings, scores, out_dir / "campaign", campaign_name=args.campaign_name)

    result = AuditResult(
        directory=directory,
        findings=findings,
        scores=scores,
        mfa=mfa_summary,
        sod_matrix=matrix,
        suggested_roles=suggested,
        packets=packets,
        integrity_issues=integrity,
        dormant_days=args.dormant_days,
    )
    result.write_json(out_dir / "findings.json")
    result.write_markdown(out_dir / "report.md")

    print(result.console_summary(top_n=args.top))
    print()
    print(f"Wrote {out_dir / 'findings.json'}, {out_dir / 'report.md'}"
          + (f" and {len(packets)} campaign packet(s) under {out_dir / 'campaign'}" if packets else ""))
    if integrity:
        print(f"WARNING: {len(integrity)} data-integrity issue(s) - see report.md")

    if args.fail_on:
        from .findings import SEVERITY_ORDER

        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            print(f"FAIL: findings at or above '{args.fail_on}' severity present")
            return 2
    return 0


def run_simulate(args: argparse.Namespace) -> int:
    directory = load_directory(args.directory)
    policy = load_policy(args.policy)
    decision = simulate(directory, args.user, args.action, args.resource, policy)
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        verdict = "ALLOW" if decision.allowed else "DENY"
        print(f"{verdict}  user={decision.user}  permission={decision.permission}")
        print(f"  stage : {decision.stage}" + (f" ({decision.rule_id})" if decision.rule_id else ""))
        print(f"  reason: {decision.reason}")
        for p in decision.paths:
            print(f"  path  : {p} -> {decision.permission}")
        if decision.trace:
            print("  trace : " + " | ".join(decision.trace))
    return 0 if decision.allowed else 1


def run_rolemine(args: argparse.Namespace) -> int:
    directory = load_directory(args.directory)
    suggestions = rolemine.mine_roles(directory, threshold=args.threshold, min_members=args.min_members)
    if args.json:
        print(json.dumps([s.to_dict() for s in suggestions], indent=2))
        return 0
    print(f"Role mining: {len(suggestions)} suggested role(s) "
          f"(Jaccard >= {args.threshold}, min members {args.min_members})")
    rows = []
    for s in suggestions:
        closest = f"{s.closest_existing_role} ({s.closest_similarity:.2f})" if s.closest_existing_role else "-"
        rows.append([str(s.cluster_id), s.name, str(len(s.members)), str(len(s.core_permissions)),
                     str(len(s.optional_permissions)), closest, f"{s.cohesion:.2f}"])
    print(render_table(["#", "suggested role", "members", "core", "optional", "closest existing", "cohesion"], rows))
    for s in suggestions:
        print()
        print(f"[{s.cluster_id}] {s.name}: {len(s.members)} members; titles "
              + ", ".join(f"{t} x{c}" for t, c in s.dominant_titles))
        print("    core     : " + ", ".join(s.core_permissions))
        if s.optional_permissions:
            print("    optional : " + ", ".join(s.optional_permissions))
    return 0


def run_explain(args: argparse.Namespace) -> int:
    directory = load_directory(args.directory)
    user = directory.user_by_name(args.user)
    if user is None:
        print(f"user '{args.user}' not found", file=sys.stderr)
        return 1
    findings: List[Finding] = []
    findings += least_privilege.analyze_user(directory, user)
    findings += dormant.analyze_user(directory, user, args.dormant_days)
    findings += [f for f in mfa.analyze(directory) if f.user_id == user.id]
    findings += [f for f in sod.analyze(directory, sod.load_rules(args.sod_rules)) if f.user_id == user.id]
    score = risk.score_user(directory, user, findings)

    print(f"{user.display_name} <{user.email}>  id={user.id}  {user.title} / {user.department}")
    print(f"  status={user.status} enabled={user.enabled} mfa={user.mfa_enrolled} "
          f"last_login={user.last_login} manager={user.manager_id}")
    if user.past_titles:
        print(f"  former titles: {', '.join(user.past_titles)}")
    print(f"  risk score: {score.score} ({score.level})")
    for r in score.reasons:
        print(f"    {r}")
    print()
    print("Effective permissions and grant paths:")
    baseline = directory.baseline_for_title(user.title)
    grants = directory.grants_for(user)
    rows = []
    for perm in sorted({g.permission for g in grants}):
        paths = sorted({" -> ".join(g.path[1:]) for g in grants if g.permission == perm})
        flag = "" if perm in baseline else "EXCESS"
        rows.append([perm, directory.sensitivity(perm), flag, " | ".join(paths)])
    print(render_table(["permission", "sens", "flag", "granted via"], rows))
    if findings:
        print()
        print("Findings:")
        for f in findings:
            print(f"  [{f.severity.upper()}] {f.code}: {f.detail}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {"audit": run_audit, "simulate": run_simulate, "rolemine": run_rolemine, "explain": run_explain}
    return handlers[args.command](args)
