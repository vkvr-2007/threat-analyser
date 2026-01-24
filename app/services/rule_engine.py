def map_to_kill_chain(intel: dict, content_scan: dict) -> dict:

    whois = intel.get("whois", {})
    ssl = intel.get("ssl", {})

    domain_age = whois.get("domain_age_days")
    cert_age = ssl.get("certificate_age_days")

    reasons = []

    # Credential Access (strongest)
    if content_scan["credential_indicators"]:
        reasons.append("Credential harvesting language detected")

        if domain_age is not None and domain_age < 60:
            reasons.append("Newly registered domain")

        return {
            "current_stage": "Credential Access",
            "next_stage": "Account Takeover",
            "severity_weight": 0.9,
            "reasons": reasons,
            "mitigation_steps": [
                "Block domain",
                "Reset exposed credentials",
                "Enable MFA"
            ]
        }

    # Initial Access
    if domain_age is not None and domain_age < 60:
        reasons.append("Newly registered domain")

        if cert_age is not None and cert_age < 7:
            reasons.append("Recently issued SSL certificate")

        return {
            "current_stage": "Initial Access",
            "next_stage": "Credential Access",
            "severity_weight": 0.6,
            "reasons": reasons,
            "mitigation_steps": [
                "Warn users",
                "Block domain at gateway"
            ]
        }

    # Reconnaissance
    return {
        "current_stage": "Reconnaissance",
        "next_stage": "Initial Access",
        "severity_weight": 0.2,
        "reasons": ["No strong attack indicators"],
        "mitigation_steps": ["Monitor activity"]
    }
