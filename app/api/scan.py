from fastapi import APIRouter
from datetime import datetime

from app.db.crud import fetch_history
from app.db.crud import insert_scan
from app.models.schemas import ScanRequest
from app.services.input_utils import normalize_input
from app.services.content_scanner import scan_content
from app.services.intel_aggregator import gather_intelligence
from app.services.rule_engine import map_to_kill_chain
from app.services.scoring_engine import calculate_threat_score


router = APIRouter()

@router.get("/history")
def get_history(limit: int = 10):
    return fetch_history(limit)


@router.post("/scan")
def scan_input(request: ScanRequest):

    normalized = normalize_input(request.input_type, request.input_value)

    content_scan = scan_content(request.input_value)

    intel = {}
    if normalized["type"] == "url":
        intel = gather_intelligence(normalized["url"])

    ml_confidence = 0.75  # stub

    kill_chain = map_to_kill_chain(intel, content_scan)

    threat_score, threat_level = calculate_threat_score(
        ml_confidence,
        kill_chain["severity_weight"]
    )

    return {
    "input_type": request.input_type,
    "input_value": request.input_value,
    "current_stage": kill_chain["current_stage"],
    "next_stage": kill_chain["next_stage"],
    "threat_level": threat_level,
    "threat_score": threat_score,
    "ml_confidence": ml_confidence,
    "reasons": ", ".join(kill_chain["reasons"]),
    "timestamp": datetime.utcnow()
    }
