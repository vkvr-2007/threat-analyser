from pydantic import BaseModel

class ScanRequest(BaseModel):
    input_type: str
    input_value: str

class ScanResponse(BaseModel):
    legitimacy: str
    threat_level: str
    threat_score: float
