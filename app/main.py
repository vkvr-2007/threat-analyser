from fastapi import FastAPI
from app.api.scan import router as scan_router

app = FastAPI(
    title="Threat Analyzer",
    version="1.0"
)

app.include_router(scan_router)
