

from __future__ import annotations

from typing import Iterable, Sequence

WEIGHTS_URL = {
    "at_symbol": 18,
    "ip_host": 35,
    "punycode": 30,
    "non_ascii": 25,
    "brand_wrong_place": 30,
    "typosquatting": 28,
    "suspicious_tld": 15,
    "shortener": 12,
    "credential_keyword": 5,
    "long_url": 8,
    "deep_subdomain": 8,
    "nonstandard_port": 10,
    "double_slash": 8,
    "encoded_chars": 6,
    "dangerous_extension": 20,
    "many_query_params": 6,
}

def risk_label(pct: float) -> str:
    pct = float(pct)
    if pct < 30:
        return "Low"
    if pct < 60:
        return "Medium"
    return "High"

def combine(rule_pct: float, ml_pct: float, w_rule: float = 0.4, w_ml: float = 0.6) -> float:
    total = w_rule + w_ml
    if total <= 0:
        raise ValueError("Scoring weights must be positive.")
    value = (float(rule_pct) * w_rule + float(ml_pct) * w_ml) / total
    return max(0.0, min(100.0, value))

def apply_overrides(
    final_pct: float,
    hard_flags: Iterable[str] | None = None,
    trusted: bool = False,
) -> float:
    hard_flags = list(hard_flags or [])
    value = float(final_pct)
    if hard_flags:
        value = max(value, 70.0)
    elif trusted:
        value = min(value, 15.0)
    return max(0.0, min(100.0, value))

def make_reasons(items: Sequence[tuple[str, float]], limit: int = 5) -> list[dict]:
    cleaned = [(str(text), float(points)) for text, points in items if text]
    cleaned.sort(key=lambda x: x[1], reverse=True)
    return [{"text": text, "points": round(points, 1)} for text, points in cleaned[:limit]]

def score_from_points(points: float, max_score: float) -> float:
    if max_score <= 0:
        return 0.0
    return max(0.0, min(100.0, (float(points) / max_score) * 100.0))
