import pandas as pd
from sqlalchemy import text
from app.db.database import engine


EXCEL_FILE_PATH = "scan_history.xlsx"


def sync_scans_to_excel():
    """
    Syncs PostgreSQL scans table to Excel file
    """

    query = text("""
        SELECT
            id,
            input_type,
            input_value,
            current_stage,
            next_stage,
            threat_level,
            threat_score,
            ml_confidence,
            reasons,
            timestamp
        FROM scans
        ORDER BY timestamp DESC
    """)

    with engine.connect() as conn:
        df = pd.read_sql(query, conn)

    df.to_excel(EXCEL_FILE_PATH, index=False)
