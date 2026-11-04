"""Transparent, deterministic risk assessment; scores are not probabilities."""

DEFAULT_WEIGHTS = {
    "threat_indicator_strength": 0.25,
    "asset_impact": 0.20,
    "evidence_confidence": 0.20,
    "telemetry_quality": 0.15,
    "correlation_strength": 0.15,
    "operational_context": 0.05,
}


def _bounded(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 100 else None


def assess(event, *, threat_indicator_strength, asset_impact=None,
           evidence_confidence=None, telemetry_quality=None,
           correlation_strength=None, operational_context=None,
           weights=None):
    """Return a reproducible weighted score and per-dimension explanations.

    Inputs are ordinal assessment values in [0,100], not calibrated probabilities.
    Missing critical evidence/telemetry yields INSUFFICIENT_EVIDENCE. Remaining
    available weights are renormalized and the omitted dimensions are disclosed.
    """
    configured = dict(DEFAULT_WEIGHTS)
    if weights is not None:
        if set(weights) != set(configured):
            raise ValueError("invalid_risk_weight_keys")
        configured = {key: float(value) for key, value in weights.items()}
    if any(value < 0 for value in configured.values()) or sum(configured.values()) <= 0:
        raise ValueError("invalid_risk_weights")

    inputs = {
        "threat_indicator_strength": threat_indicator_strength,
        "asset_impact": asset_impact,
        "evidence_confidence": evidence_confidence,
        "telemetry_quality": telemetry_quality,
        "correlation_strength": correlation_strength,
        "operational_context": operational_context,
    }
    descriptions = {
        "threat_indicator_strength": "Rule or policy indicator strength; not attack probability.",
        "asset_impact": "Configured impact assessment for the affected asset.",
        "evidence_confidence": "Integrity and completeness of referenced evidence.",
        "telemetry_quality": "Validity and completeness of observed telemetry.",
        "correlation_strength": "Strength of recorded evidence relationships.",
        "operational_context": "Approved maintenance/operational context assessment.",
    }
    dimensions = {}
    missing = []
    present_weight = 0.0
    weighted_total = 0.0
    for key, raw in inputs.items():
        score = _bounded(raw)
        if score is None:
            missing.append(key)
        else:
            present_weight += configured[key]
            weighted_total += score * configured[key]
        dimensions[key] = {
            "score": score,
            "weight": configured[key],
            "reason": descriptions[key] if score is not None else "No verified input available.",
        }

    critical_missing = [key for key in ("evidence_confidence", "telemetry_quality") if dimensions[key]["score"] is None]
    if critical_missing or present_weight == 0:
        return {
            "risk_level": "INSUFFICIENT_EVIDENCE", "risk_score": None,
            "score_type": "weighted_ordinal_not_probability",
            "dimensions": dimensions,
            "explanation": ["Critical evidence or telemetry quality is unavailable; no risk tier assigned."],
            "missing_evidence": missing,
        }

    score = round(weighted_total / present_weight, 2)
    if score < 15:
        level = "INFORMATIONAL"
    elif score < 35:
        level = "LOW"
    elif score < 55:
        level = "MEDIUM"
    elif score < 75:
        level = "HIGH"
    else:
        level = "CRITICAL"
    explanation = [
        f"Weighted ordinal score {score:.2f}/100; available weights renormalized to {present_weight:.2f}.",
        "Missing dimensions were not imputed and are listed separately.",
    ]
    return {
        "risk_level": level, "risk_score": score,
        "score_type": "weighted_ordinal_not_probability",
        "dimensions": dimensions, "explanation": explanation,
        "missing_evidence": missing,
    }
