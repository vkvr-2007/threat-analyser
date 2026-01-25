from fastapi import APIRouter
from datetime import datetime
from fastapi import UploadFile, File
import tempfile
import os


from app.services.stego_text import analyze_text_binary_steganography
from app.services.stego_image import analyze_image_steganography
from app.services.excel_sync import sync_scans_to_excel
from app.models.schemas import ScanRequest
from app.services.input_utils import normalize_input
from app.services.content_scanner import scan_content
from app.services.intel_aggregator import gather_intelligence
from app.services.rule_engine import map_to_kill_chain
from app.services.scoring_engine import calculate_threat_score
from app.db.crud import insert_scan, fetch_history
from app.services.stego_audio import analyze_audio_steganography


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


@router.post("/scan/image")
async def scan_image(file: UploadFile = File(...)):
    """
    Image steganography scan
    """

    # Save temp file
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        result = analyze_image_steganography(tmp_path)

        # Kill chain mapping
        if result["confidence"] == "High":
            kill_chain = {
                "current_stage": "Command and Control",
                "next_stage": "Execution",
                "severity_weight": 0.9,
                "reasons": ["Hidden payload detected in image"]
            }
        else:
            kill_chain = {
                "current_stage": "Reconnaissance",
                "next_stage": "Initial Access",
                "severity_weight": 0.2,
                "reasons": ["No malicious payload is found"]
            }

        return {
            "filename": file.filename,
            "stego_analysis": result,
            "kill_chain": kill_chain
        }

    finally:
        os.remove(tmp_path)


@router.post("/scan/file")
async def scan_text_or_binary(file: UploadFile = File(...)):
    """
    Text / binary file steganography scan
    """

    import tempfile
    import os

    suffix = os.path.splitext(file.filename)[1]

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        result = analyze_text_binary_steganography(tmp_path)

        # Kill chain mapping
        if result["confidence"] == "High":
            kill_chain = {
                "current_stage": "Command and Control",
                "next_stage": "Execution",
                "severity_weight": 0.9,
                "reasons": ["Hidden command or instructions found in file"]
            }
        elif result["confidence"] == "Medium":
            kill_chain = {
                "current_stage": "Delivery",
                "next_stage": "Execution",
                "severity_weight": 0.6,
                "reasons": ["Encoded payload detected"]
            }
        else:
            kill_chain = {
                "current_stage": "Reconnaissance",
                "next_stage": "Initial Access",
                "severity_weight": 0.2,
                "reasons": ["No malicious content detected"]
            }

        return {
            "filename": file.filename,
            "stego_analysis": result,
            "kill_chain": kill_chain
        }

    finally:
        os.remove(tmp_path)


@router.post("/scan/audio")
async def scan_audio(file: UploadFile = File(...)):
    """
    Audio steganography scan
    """

    import tempfile
    import os

    suffix = os.path.splitext(file.filename)[1]

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        result = analyze_audio_steganography(tmp_path)

        # Kill chain mapping
        if result["confidence"] == "High":
            kill_chain = {
                "current_stage": "Command and Control",
                "next_stage": "Execution",
                "severity_weight": 0.9,
                "reasons": ["Hidden instructions or payload detected in audio"]
            }
        elif result["confidence"] == "Medium":
            kill_chain = {
                "current_stage": "Delivery",
                "next_stage": "Execution",
                "severity_weight": 0.6,
                "reasons": ["Encoded or metadata payload detected"]
            }
        else:
            kill_chain = {
                "current_stage": "Reconnaissance",
                "next_stage": "Initial Access",
                "severity_weight": 0.2,
                "reasons": ["No steganographic indicators found"]
            }

        return {
            "filename": file.filename,
            "stego_analysis": result,
            "kill_chain": kill_chain
        }

    finally:
        os.remove(tmp_path)
