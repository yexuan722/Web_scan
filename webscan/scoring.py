"""健康评分：noisy-OR 模型，可复算、可解释。

风险指数 = 1 - Π(1 - base[severity] × confidence)
健康参考分 = round(100 × (1 - 风险指数))
"""

from __future__ import annotations

from typing import Any

from . import config
from .models import Finding, SEV_RANK, SEVERITIES


def compute_score(findings: list[Finding]) -> dict[str, Any]:
    probability = 1.0
    items = []
    for f in findings:
        base = config.SEVERITY_BASE.get(f.severity, 0.0)
        if base <= 0:
            continue
        p = base * max(0.0, min(1.0, f.confidence))
        probability *= 1.0 - p
        items.append({"rule": f.rule_id, "severity": f.severity, "p": round(p, 4)})

    risk = 1.0 - probability
    score = int(round(100 * (1 - risk)))
    score = max(0, min(100, score))

    grade, label = _grade(score)

    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "score": score,
        "grade": grade,
        "grade_label": label,
        "risk": round(risk, 4),
        "counts": counts,
        "items": sorted(items, key=lambda x: x["p"], reverse=True),
        "verified": sum(1 for f in findings if f.verified),
        "total": len(findings),
    }


def _grade(score: int) -> tuple[str, str]:
    for threshold, label, key in config.GRADE_BANDS:
        if score >= threshold:
            return key, label
    return "bad", "危险"


def severity_order(sev: str) -> int:
    return SEV_RANK.get(sev, 9)
