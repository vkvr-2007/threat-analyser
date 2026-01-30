import os
from app.services.content_scanner import scan_content
from app.services.content_scanner import scan_text_for_encodings



def scan_file_static(file_path: str) -> dict:
    """
    Master file scanning function.
    This NEVER executes files.
    """

    file_ext = os.path.splitext(file_path)[1].lower()

    result = {
        "file_path": file_path,
        "file_extension": file_ext,
        "payload_detected": False,
        "decoded_content": None,
        "indicators": [],
        "analysis_notes": []
    }

    # ---- TEXT-BASED FILES ----
    if file_ext in [".txt", ".csv", ".rtf", ".log"]:
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()

            encoding_result = scan_text_for_encodings(content)

            result["payload_detected"] = encoding_result["payload_detected"]
            result["decoded_content"] = encoding_result["decoded_payloads"]

            if encoding_result["payload_detected"]:
                result["indicators"].append("Encoded or hidden payload detected")
                result["has_suspicious_content"] = True

        except Exception as e:
            result["analysis_notes"].append(f"Text scan failed: {e}")

    # ---- DOCUMENTS ----
    elif file_ext in [".docx", ".docm", ".pdf"]:
        content_result = scan_content(file_path)
        result.update(content_result)

    # ---- ARCHIVES ----
    elif file_ext in [".zip", ".rar", ".7z"]:
        result["analysis_notes"].append(
            "Archive detected. Contents not extracted for safety."
        )

    # ---- EVERYTHING ELSE ----
    else:
        result["analysis_notes"].append(
            "File type not deeply scanned. Metadata only."
        )

    return result
