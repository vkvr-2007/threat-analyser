from fastapi import APIRouter
from datetime import datetime

from app.models.schemas import ScanRequest
from app.services.input_utils import normalize_input
from app.services.content_scanner import scan_content
from app.services.intel_aggregator import gather_intelligence
from app.services.rule_engine import map_to_kill_chain
from app.services.scoring_engine import calculate_threat_score
from app.db.crud import insert_scan, fetch_history

router = APIRouter()


@router.post("/scan")
def scan_input(request: ScanRequest):
    """
    Main scan endpoint
    """

    # 1️⃣ Normalize input
    normalized = normalize_input(request.input_type, request.input_value)

    # 2️⃣ Content scanning (works for URL + text)
    content_scan = scan_content(request.input_value)

    # 3️⃣ Domain intelligence (URL only)
    intel = {}
    if normalized["type"] == "url":
        intel = gather_intelligence(normalized["url"])

    # 4️⃣ ML confidence (stub for now)
    ml_confidence = 0.75

    # 5️⃣ Kill chain mapping
    kill_chain = map_to_kill_chain(intel, content_scan)

    # 6️⃣ Threat scoring
    threat_score, threat_level = calculate_threat_score(
        ml_confidence,
        kill_chain["severity_weight"]
    )

    # 7️⃣ Store scan in PostgreSQL (SAFE)
    try:
        insert_scan({
            "input_type": request.input_type,
            "input_value": request.input_value,
            "current_stage": kill_chain["current_stage"],
            "next_stage": kill_chain["next_stage"],
            "threat_level": threat_level,
            "threat_score": threat_score,
            "ml_confidence": ml_confidence,
            "reasons": ", ".join(kill_chain.get("reasons", [])),
            "timestamp": datetime.utcnow()
        })
    except Exception as e:
        # DB failure should NEVER break scanning
        print("⚠️ DB insert failed:", e)

    # 8️⃣ Final response
    return {
        "input_type": request.input_type,
        "input_value": request.input_value,
        "content_analysis": content_scan,
        "domain_intelligence": intel,
        "kill_chain": kill_chain,
        "threat_score": threat_score,
        "threat_level": threat_level,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/history")
def get_history(limit: int = 10):
    """
    Fetch past scans from DB
    """
    return fetch_history(limit)
