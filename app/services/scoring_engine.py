def calculate_threat_score(ml_confidence: float, severity_weight: float) -> tuple:
    """
    Returns threat_score and threat_level
    """

    score = (ml_confidence * 0.5) + (severity_weight * 0.5)

    if score < 0.3:
        level = "Low"
    elif score < 0.6:
        level = "Medium"
    elif score < 0.8:
        level = "High"
    else:
        level = "Critical"

    return round(score, 2), level
