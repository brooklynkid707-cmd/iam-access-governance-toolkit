"""Role mining via Jaccard clustering of effective permission sets.

The goal of role mining is bottom-up: look at what people *actually* hold and
propose roles that would cover them with the fewest direct grants.  The
algorithm here is deliberately simple and explainable:

1. Compute each active human's effective permission set.
2. Collapse users with identical sets into one "signature" (frequency-weighted).
3. Greedy single-pass clustering: walk signatures from most to least common and
   attach each to the first cluster whose seed has Jaccard similarity >=
   ``threshold``; otherwise start a new cluster.
4. For each cluster with at least ``min_members`` users emit a suggested role:
   the *core* permissions (held by every member), the *optional* ones (held by
   some), the dominant titles/departments, and the closest existing role.

Jaccard(A, B) = |A n B| / |A u B| - 1.0 means identical, 0.0 means disjoint.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from ..models import Directory, User


def jaccard(a: Set[str] | FrozenSet[str], b: Set[str] | FrozenSet[str]) -> float:
    """Jaccard similarity of two sets (1.0 for two empty sets)."""
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


@dataclass
class SuggestedRole:
    cluster_id: int
    name: str
    members: List[str]
    core_permissions: List[str]
    optional_permissions: List[str]
    dominant_titles: List[Tuple[str, int]]
    dominant_departments: List[Tuple[str, int]]
    closest_existing_role: Optional[str]
    closest_similarity: float
    cohesion: float  # mean Jaccard of each member to the core

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "suggested_name": self.name,
            "member_count": len(self.members),
            "members": self.members,
            "core_permissions": self.core_permissions,
            "optional_permissions": self.optional_permissions,
            "dominant_titles": [{"title": t, "count": c} for t, c in self.dominant_titles],
            "dominant_departments": [{"department": d, "count": c} for d, c in self.dominant_departments],
            "closest_existing_role": self.closest_existing_role,
            "closest_similarity": round(self.closest_similarity, 3),
            "cohesion": round(self.cohesion, 3),
        }


@dataclass
class _Cluster:
    seed: FrozenSet[str]
    users: List[User] = field(default_factory=list)
    sets: List[FrozenSet[str]] = field(default_factory=list)


def mine_roles(
    directory: Directory,
    threshold: float = 0.7,
    min_members: int = 3,
    include_service: bool = False,
) -> List[SuggestedRole]:
    """Cluster users by permission similarity and return suggested roles."""
    if not 0.0 < threshold <= 1.0:
        raise ValueError("threshold must be in (0, 1]")

    signatures: Dict[FrozenSet[str], List[User]] = {}
    for user in directory.users.values():
        if user.status == "terminated" or not user.enabled:
            continue
        if user.account_type != "human" and not include_service:
            continue
        perms = frozenset(directory.effective_permissions(user))
        if perms:
            signatures.setdefault(perms, []).append(user)

    clusters: List[_Cluster] = []
    for sig, users in sorted(signatures.items(), key=lambda kv: (-len(kv[1]), sorted(kv[0]))):
        best: Optional[_Cluster] = None
        best_score = 0.0
        for cluster in clusters:
            score = jaccard(sig, cluster.seed)
            if score >= threshold and score > best_score:
                best, best_score = cluster, score
        if best is None:
            best = _Cluster(seed=sig)
            clusters.append(best)
        best.users.extend(users)
        best.sets.extend([sig] * len(users))

    suggestions: List[SuggestedRole] = []
    for idx, cluster in enumerate(clusters, start=1):
        if len(cluster.users) < min_members:
            continue
        core: Set[str] = set(cluster.sets[0])
        union: Set[str] = set()
        for s in cluster.sets:
            core &= s
            union |= s
        titles = Counter(u.title for u in cluster.users).most_common(3)
        depts = Counter(u.department for u in cluster.users).most_common(3)
        closest, sim = _closest_role(directory, core)
        cohesion = sum(jaccard(core, s) for s in cluster.sets) / len(cluster.sets)
        suggestions.append(
            SuggestedRole(
                cluster_id=idx,
                name=_suggest_name(titles, depts),
                members=sorted(u.username for u in cluster.users),
                core_permissions=sorted(core),
                optional_permissions=sorted(union - core),
                dominant_titles=titles,
                dominant_departments=depts,
                closest_existing_role=closest,
                closest_similarity=sim,
                cohesion=cohesion,
            )
        )
    suggestions.sort(key=lambda s: -len(s.members))
    return suggestions


def _closest_role(directory: Directory, core: Set[str]) -> Tuple[Optional[str], float]:
    """Closest existing bundle: a title baseline (``title:<T>``) or a single role.

    Title baselines are unions of roles, which is what a cluster of real users
    usually looks like, so they are compared first; single roles are included
    for directories without ``title_baselines``.
    """
    best_id, best_score = None, 0.0
    for title in directory.title_baselines:
        score = jaccard(core, directory.baseline_for_title(title))
        if score > best_score:
            best_id, best_score = f"title:{title}", score
    for role in directory.roles.values():
        score = jaccard(core, set(role.permissions))
        if score > best_score:
            best_id, best_score = f"role:{role.id}", score
    return best_id, best_score


def _suggest_name(titles: List[Tuple[str, int]], depts: List[Tuple[str, int]]) -> str:
    if titles:
        title, count = titles[0]
        total = sum(c for _, c in titles)
        if count / total >= 0.6:
            return "mined_" + title.lower().replace(" ", "_")
    if depts:
        return "mined_" + depts[0][0].lower().replace(" ", "_") + "_common"
    return "mined_role"
