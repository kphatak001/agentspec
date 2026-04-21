"""Risk scoring for threat models."""

from __future__ import annotations
from .model import Finding, ThreatModel, Architecture


def score(arch: Architecture, findings: list[Finding]) -> ThreatModel:
    if not findings:
        return ThreatModel(architecture=arch, findings=findings, overall_score=0.0, overall_rating="LOW")

    top = sorted(findings, key=lambda f: f.score, reverse=True)[:5]
    weights = [5, 4, 3, 2, 1]
    total_w = sum(weights[:len(top)])
    overall = sum(f.score * w for f, w in zip(top, weights)) / total_w

    if overall >= 70:
        rating = "CRITICAL"
    elif overall >= 50:
        rating = "HIGH"
    elif overall >= 30:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    return ThreatModel(
        architecture=arch,
        findings=findings,
        overall_score=round(overall, 1),
        overall_rating=rating,
    )
