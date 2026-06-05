"""Shared protocol query parsing and resolution."""

import re

from utils.protocols_utils import rank_protocols


def resolve_protocols(
    query: str,
    protocol_candidates: list[str],
    *,
    min_prefix_len: int = 3,
    max_contains_matches: int = 5,
    max_prefix_matches: int = 3,
    max_fuzzy: int = 10,
) -> list[str]:
    q_low = query.lower().strip()
    words = q_low.split()

    p_exact, p_contains, p_prefix = [], [], []

    for proto in protocol_candidates:
        c_low = proto.lower()

        for word in words:
            if c_low == word:
                if proto not in p_exact:
                    p_exact.append(proto)
                break

            if c_low.startswith(word) and len(word) >= min_prefix_len:
                if proto not in p_prefix and len(p_prefix) < max_prefix_matches:
                    p_prefix.append(proto)
                break

            if word in c_low:
                if proto not in p_contains and len(p_contains) < max_contains_matches:
                    p_contains.append(proto)
                break

    return (p_exact + p_prefix + p_contains)[:max_fuzzy]


def parse_shorthand_query(raw: str):
    s = (raw or "").strip().lower()
    if not s:
        return [], []

    tokens = [t for t in re.compile(r"[,\s]+").split(s) if t]
    include, exclude = [], []

    for t in tokens:
        if t.startswith("!"):
            v = t[1:].strip()
            if v:
                exclude.append(v)
        else:
            include.append(t)

    def dedup(xs):
        out, seen = [], set()
        for x in xs:
            if not x or x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    return dedup(include), dedup(exclude)
