import re
from pymediainfo import MediaInfo


BASE64_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:==|=)?")

SUSPICIOUS_KEYWORDS = [
    "http", "https", "cmd", "powershell",
    "bash", "curl", "wget",
    "payload", "execute", "connect", "c2"
]


def extract_ascii_strings(data: bytes, min_len=6):
    results = []
    current = b""

    for b in data:
        if 32 <= b <= 126:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                results.append(current.decode(errors="ignore"))
            current = b""

    if len(current) >= min_len:
        results.append(current.decode(errors="ignore"))

    return results


def analyze_video_steganography(file_path: str) -> dict:
    findings = {
        "metadata_text": [],
        "ascii_strings": [],
        "base64_detected": False,
        "suspicious_keywords": [],
        "extra_data_detected": False,
        "confidence": "Low"
    }

    # 1️⃣ Container metadata scan
    try:
        media_info = MediaInfo.parse(file_path)
        for track in media_info.tracks:
            for key, value in track.to_data().items():
                val = str(value)
                if len(val) > 15:
                    findings["metadata_text"].append(val)
    except Exception:
        pass

    # 2️⃣ Read raw bytes
    with open(file_path, "rb") as f:
        raw = f.read()

    # 3️⃣ Extract readable strings
    strings = extract_ascii_strings(raw)
    findings["ascii_strings"] = strings[:10]

    # 4️⃣ Keyword detection
    for s in strings:
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in s.lower():
                findings["suspicious_keywords"].append(kw)

    # 5️⃣ Base64 detection
    if BASE64_REGEX.search(raw.decode(errors="ignore")):
        findings["base64_detected"] = True

    # 6️⃣ Appended data detection (simple heuristic)
    # MP4 files usually end with 'moov' or 'mdat'
    tail = raw[-4096:]
    if b"mdat" not in tail and b"moov" not in tail:
        findings["extra_data_detected"] = True

    # 7️⃣ Confidence logic (STRICT)
    if findings["suspicious_keywords"] or findings["extra_data_detected"]:
        findings["confidence"] = "High"
    elif findings["base64_detected"] or findings["metadata_text"]:
        findings["confidence"] = "Medium"
    else:
        findings["confidence"] = "Low"

    return findings
