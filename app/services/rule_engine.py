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



def map_file_to_kill_chain(file_analysis: dict) -> dict:
    """
    Maps decoded file content to cyber kill chain stages
    """

    decoded = file_analysis.get("decoded_content", [])
    reasons = []

    if not decoded:
        return {
            "current_stage": "Delivery",
            "next_stage": "Unknown",
            "severity_weight": 0.2,
            "reasons": ["No active payload detected"],
            "impact_prediction": ["File appears benign"],
            "mitigation_steps": ["Standard antivirus scan"]
        }

    combined_text = " ".join(
        item.get("decoded", "").lower() for item in decoded
    )

    # ---- EXECUTION ----
    if any(x in combined_text for x in [
        "powershell", "cmd.exe", "bash", "sh ", "python "
    ]):
        return {
            "current_stage": "Execution",
            "next_stage": "Persistence",
            "severity_weight": 0.9,
            "reasons": ["Decoded content contains command execution patterns"],
            "impact_prediction": [
                "Command execution on host",
                "Payload download",
                "Malware installation"
            ],
            "mitigation_steps": [
                "Do not open the file",
                "Disable script execution",
                "Isolate affected system"
            ]
        }

    # ---- DELIVERY / C2 ----
    if any(x in combined_text for x in [
        "http://", "https://", "wget", "curl"
    ]):
        return {
            "current_stage": "Delivery",
            "next_stage": "Execution",
            "severity_weight": 0.75,
            "reasons": ["External resource reference detected"],
            "impact_prediction": [
                "Malicious payload download",
                "Command and Control communication"
            ],
            "mitigation_steps": [
                "Block outbound connections",
                "Inspect network traffic"
            ]
        }

    # ---- CREDENTIAL ACCESS ----
    if any(x in combined_text for x in [
        "password", "login", "credential", "token"
    ]):
        return {
            "current_stage": "Credential Access",
            "next_stage": "Account Takeover",
            "severity_weight": 0.85,
            "reasons": ["Credential-related indicators detected"],
            "impact_prediction": [
                "Credential theft",
                "Account compromise"
            ],
            "mitigation_steps": [
                "Force password resets",
                "Enable MFA"
            ]
        }

    # ---- FALLBACK ----
    return {
        "current_stage": "Delivery",
        "next_stage": "Execution",
        "severity_weight": 0.4,
        "reasons": ["Obfuscated content detected but no clear command"],
        "impact_prediction": ["Potential malicious activity"],
        "mitigation_steps": ["Manual analysis recommended"]
    }
