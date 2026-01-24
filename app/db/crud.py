from sqlalchemy.sql import text
from app.db.database import SessionLocal


def insert_scan(data: dict):
    db = SessionLocal()
    try:
        query = text("""
            INSERT INTO scans (
                input_type, input_value,
                current_stage, next_stage,
                threat_level, threat_score,
                ml_confidence, reasons, timestamp
            ) VALUES (
                :input_type, :input_value,
                :current_stage, :next_stage,
                :threat_level, :threat_score,
                :ml_confidence, :reasons, :timestamp
            )
        """)

        db.execute(query, data)
        db.commit()
    finally:
        db.close()


def fetch_history(limit: int = 10):
    db = SessionLocal()
    try:
        query = text("""
            SELECT * FROM scans
            ORDER BY timestamp DESC
            LIMIT :limit
        """)
        result = db.execute(query, {"limit": limit})
        return [dict(row) for row in result]
    finally:
        db.close()
