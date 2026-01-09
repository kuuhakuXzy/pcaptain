from typing import List, Tuple
from rapidfuzz.distance import DamerauLevenshtein
from rapidfuzz.fuzz import partial_ratio


def protocol_distance(query: str, candidate: str) -> float:
    """
    Calculate the distance between a query string and a candidate protocol name.
    
    Args:
        query: The search query
        candidate: The protocol name to compare against
        
    Returns:
        A distance score (lower is better match)
    """
    q = query.lower()
    c = candidate.lower()

    # Normalized edit distance
    edit = DamerauLevenshtein.normalized_distance(q, c)

    # Prefix similarity (helps "ipv" → "ipv6")
    prefix = 1 - (partial_ratio(q, c) / 100)

    return 0.7 * edit + 0.3 * prefix


def rank_protocols(query: str, candidates: List[str], max_dist: float = 0.5) -> List[str]:
    """
    Rank protocols by fuzzy match similarity to the query.
    
    Args:
        query: The search query
        candidates: List of protocol names to rank
        max_dist: Maximum distance threshold (protocols with distance > max_dist are filtered out)
        
    Returns:
        List of protocol names ranked by similarity
    """
    scored = [
        (p, protocol_distance(query, p))
        for p in candidates
    ]
    return [
        p for p, d in sorted(scored, key=lambda x: x[1])
        if d <= max_dist
    ]
