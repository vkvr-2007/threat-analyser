from fastapi import APIRouter
from datetime import datetime

from app.services.excel_sync import sync_scans_to_excel
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
    
    """ main scan endpoint"""

    # input normalization
    normalized = normalize_input(request.input_type, request.input_value)

    # content scanning
    content_scan = scan_content(request.input_value)

    # domain intelligence
    intel = {}
    if normalized["type"] == "url":
        intel = gather_intelligence(normalized["url"])

    # ml confidence (sub for now)
    ml_confidence = 0.75

    # 5️kill chain mapping
    kill_chain = map_to_kill_chain(intel, content_scan)

    # threat score
    threat_score, threat_level = calculate_threat_score(
        ml_confidence,
        kill_chain["severity_weight"]
    )

    # database insertion
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
        print("⚠️ DB insert failed:", e)

    # excel file data
    try:
        sync_scans_to_excel()
    except Exception as e:
        print("⚠️ Excel sync failed:", e)
        print("⚠️ DB insert failed:", e)

    # response
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
