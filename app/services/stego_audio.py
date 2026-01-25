import re
import wave
from mutagen import File as MutagenFile


BASE64_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:==|=)?")

SUSPICIOUS_KEYWORDS = [
    "http", "https", "cmd", "powershell",
    "bash", "curl", "wget", "execute",
    "payload", "connect"
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


def analyze_audio_steganography(file_path: str) -> dict:
    findings = {
        "metadata_text": [],
        "ascii_strings": [],
        "base64_detected": False,
        "suspicious_keywords": [],
        "extra_data_detected": False,
        "confidence": "Low"
    }

    # 1️⃣ Metadata scan (ID3, comments)
    try:
        audio = MutagenFile(file_path)
        if audio and audio.tags:
            for k, v in audio.tags.items():
                val = str(v)
                if len(val) > 10:
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

    # 6️⃣ WAV structure check (extra appended data)
    try:
        with wave.open(file_path, "rb") as w:
            frames = w.getnframes()
            expected_size = frames * w.getsampwidth() * w.getnchannels()
            header_size = 44  # standard WAV header
            if len(raw) > expected_size + header_size + 1024:
                findings["extra_data_detected"] = True
    except Exception:
        pass  # non-WAV files

    # 7️⃣ Confidence logic (STRICT)
    if findings["suspicious_keywords"] or findings["extra_data_detected"]:
        findings["confidence"] = "High"
    elif findings["base64_detected"] or findings["metadata_text"]:
        findings["confidence"] = "Medium"
    else:
        findings["confidence"] = "Low"

    return findings
