"""Report rendering: JSON, Markdown and a plain-text console table.

No third-party table libraries - the console renderer is a small fixed-width
formatter so the tool works anywhere Python does.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .analyzers.mfa import MfaSummary
from .analyzers.risk import RiskScore
from .analyzers.rolemine import SuggestedRole
from .analyzers.sod import SodMatrix
from .campaign import PacketSummary
from .findings import SEVERITY_ORDER, Finding, sort_findings
from .models import Directory


@dataclass
class AuditResult:
    """Everything an audit run produced, ready to be rendered."""

    directory: Directory
    findings: List[Finding]
    scores: List[RiskScore]
    mfa: MfaSummary
    sod_matrix: SodMatrix
    suggested_roles: List[SuggestedRole] = field(default_factory=list)
    packets: List[PacketSummary] = field(default_factory=list)
    integrity_issues: List[str] = field(default_factory=list)
    dormant_days: int = 90

    # ------------------------------------------------------------- summaries
    def severity_counts(self) -> Dict[str, int]:
        counts = Counter(f.severity for f in self.findings)
        return {s: counts.get(s, 0) for s in sorted(SEVERITY_ORDER, key=lambda s: -SEVERITY_ORDER[s])}

    def code_counts(self) -> Dict[str, int]:
        return dict(sorted(Counter(f.code for f in self.findings).items(), key=lambda kv: -kv[1]))

    def level_counts(self) -> Dict[str, int]:
        counts = Counter(s.level for s in self.scores)
        return {lvl: counts.get(lvl, 0) for lvl in ("critical", "high", "medium", "low", "none")}

    # ----------------------------------------------------------------- JSON
    def to_dict(self) -> Dict[str, Any]:
        d = self.directory
        return {
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "as_of": d.as_of.isoformat(),
            "source_meta": d.meta,
            "inventory": {
                "users": len(d.users),
                "groups": len(d.groups),
                "roles": len(d.roles),
                "permissions": len(d.permissions),
                "privileged_users": sum(1 for u in d.users.values() if d.is_privileged_user(u)),
            },
            "thresholds": {"dormant_days": self.dormant_days},
            "summary": {
                "findings_by_severity": self.severity_counts(),
                "findings_by_code": self.code_counts(),
                "users_by_risk_level": self.level_counts(),
            },
            "mfa": self.mfa.to_dict(),
            "sod_matrix": self.sod_matrix.to_dict(),
            "risk_scores": [s.to_dict() for s in self.scores],
            "findings": [f.to_dict() for f in sort_findings(self.findings)],
            "suggested_roles": [r.to_dict() for r in self.suggested_roles],
            "campaign_packets": [
                {"reviewer": p.reviewer, "file": p.path.name, "users": p.users, "rows": p.rows, "flagged_rows": p.flagged_rows}
                for p in self.packets
            ],
            "integrity_issues": self.integrity_issues,
        }

    def write_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    # ------------------------------------------------------------- Markdown
    def to_markdown(self, top_n: int = 15) -> str:
        d = self.directory
        sev = self.severity_counts()
        lines: List[str] = []
        lines.append("# Access Review Report")
        lines.append("")
        lines.append(f"Snapshot date: **{d.as_of.isoformat()}** | Source: `{d.meta.get('source', 'directory export')}`")
        lines.append("")
        lines.append("## Inventory")
        lines.append("")
        lines.append("| Users | Groups | Roles | Permissions | Privileged users |")
        lines.append("|---:|---:|---:|---:|---:|")
        priv = sum(1 for u in d.users.values() if d.is_privileged_user(u))
        lines.append(f"| {len(d.users)} | {len(d.groups)} | {len(d.roles)} | {len(d.permissions)} | {priv} |")
        lines.append("")
        lines.append("## Findings by severity")
        lines.append("")
        lines.append("| Critical | High | Medium | Low | Info |")
        lines.append("|---:|---:|---:|---:|---:|")
        lines.append(f"| {sev['critical']} | {sev['high']} | {sev['medium']} | {sev['low']} | {sev['info']} |")
        lines.append("")
        lines.append("## Findings by check")
        lines.append("")
        lines.append("| Code | Count |")
        lines.append("|---|---:|")
        for code, n in self.code_counts().items():
            lines.append(f"| {code} | {n} |")
        lines.append("")
        lines.append("## MFA compliance")
        lines.append("")
        m = self.mfa
        lines.append(f"- Human accounts enrolled: **{m.humans_enrolled}/{m.humans_total}** ({m.human_coverage:.1f}%)")
        lines.append(
            f"- Privileged accounts enrolled: **{m.privileged_enrolled}/{m.privileged_total}** ({m.privileged_coverage:.1f}%)"
        )
        lines.append(f"- Service accounts (excluded from MFA requirement): {m.service_accounts}")
        if m.unenrolled_by_department:
            lines.append("- Unenrolled by department: " + ", ".join(f"{k} ({v})" for k, v in sorted(m.unenrolled_by_department.items())))
        lines.append("")
        lines.append("## Separation-of-duties conflict matrix")
        lines.append("")
        lines.append("| Rule | Users in conflict | Usernames |")
        lines.append("|---|---:|---|")
        for rule_id, n in self.sod_matrix.rule_hits.items():
            users = ", ".join(self.sod_matrix.rule_users.get(rule_id, [])[:8])
            if len(self.sod_matrix.rule_users.get(rule_id, [])) > 8:
                users += ", ..."
            lines.append(f"| {rule_id} | {n} | {users} |")
        lines.append("")
        lines.append(f"## Top {top_n} riskiest identities")
        lines.append("")
        lines.append("| # | User | Title | Dept | Score | Level | Why |")
        lines.append("|---:|---|---|---|---:|---|---|")
        for i, s in enumerate(self.scores[:top_n], start=1):
            why = "<br>".join(s.reasons) if s.reasons else "-"
            lines.append(f"| {i} | {s.username} | {s.title} | {s.department} | {s.score} | {s.level} | {why} |")
        lines.append("")
        lines.append("## Critical and high findings")
        lines.append("")
        for f in sort_findings(self.findings):
            if f.severity not in ("critical", "high"):
                continue
            lines.append(f"- **[{f.severity.upper()}] {f.code}** `{f.username}` ({f.title}): {f.detail}")
        lines.append("")
        if self.suggested_roles:
            lines.append("## Role mining suggestions")
            lines.append("")
            lines.append("| Cluster | Suggested role | Members | Core perms | Optional perms | Closest existing role | Cohesion |")
            lines.append("|---:|---|---:|---:|---:|---|---:|")
            for r in self.suggested_roles:
                closest = f"{r.closest_existing_role} ({r.closest_similarity:.2f})" if r.closest_existing_role else "-"
                lines.append(
                    f"| {r.cluster_id} | {r.name} | {len(r.members)} | {len(r.core_permissions)} | "
                    f"{len(r.optional_permissions)} | {closest} | {r.cohesion:.2f} |"
                )
            lines.append("")
        if self.packets:
            lines.append("## Access-review campaign packets")
            lines.append("")
            lines.append("| Reviewer | File | Users | Entitlement rows | Flagged rows |")
            lines.append("|---|---|---:|---:|---:|")
            for p in self.packets:
                lines.append(f"| {p.reviewer} | {p.path.name} | {p.users} | {p.rows} | {p.flagged_rows} |")
            lines.append("")
        if self.integrity_issues:
            lines.append("## Data integrity issues")
            lines.append("")
            for issue in self.integrity_issues:
                lines.append(f"- {issue}")
            lines.append("")
        return "\n".join(lines)

    def write_markdown(self, path: Path) -> None:
        path.write_text(self.to_markdown(), encoding="utf-8")

    # -------------------------------------------------------------- console
    def console_summary(self, top_n: int = 10) -> str:
        d = self.directory
        sev = self.severity_counts()
        lvl = self.level_counts()
        out: List[str] = []
        out.append(f"IAM Access Governance Toolkit - audit of {len(d.users)} users as of {d.as_of.isoformat()}")
        out.append("")
        out.append(
            "Findings: "
            + "  ".join(f"{k}={v}" for k, v in sev.items() if k != "info")
            + f"  total={len(self.findings)}"
        )
        out.append(
            "Users by risk level: " + "  ".join(f"{k}={v}" for k, v in lvl.items())
        )
        m = self.mfa
        out.append(
            f"MFA coverage: humans {m.humans_enrolled}/{m.humans_total} ({m.human_coverage:.1f}%), "
            f"privileged {m.privileged_enrolled}/{m.privileged_total} ({m.privileged_coverage:.1f}%)"
        )
        out.append("")
        out.append("Findings by check:")
        out.append(render_table(["code", "count"], [[c, str(n)] for c, n in self.code_counts().items()]))
        out.append("")
        out.append("SoD conflicts by rule:")
        out.append(
            render_table(
                ["rule", "users"],
                [[r, str(n)] for r, n in self.sod_matrix.rule_hits.items()],
            )
        )
        out.append("")
        out.append(f"Top {top_n} riskiest identities:")
        rows = []
        for s in self.scores[:top_n]:
            rows.append([s.username, s.title[:26], s.department, str(s.score), s.level, ", ".join(s.finding_codes)[:48]])
        out.append(render_table(["user", "title", "dept", "score", "level", "findings"], rows))
        return "\n".join(out)


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """Fixed-width ASCII table."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = "|" + "|".join(f" {{:<{w}}} " for w in widths) + "|"
    lines = [sep, fmt.format(*headers), sep]
    for row in rows:
        lines.append(fmt.format(*[str(c) for c in row]))
    lines.append(sep)
    return "\n".join(lines)
