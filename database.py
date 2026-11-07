import sqlite3

def create_database():
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            result TEXT,
            confidence REAL,
            date_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("PRAGMA table_info(detection_history)")
    columns = [column[1] for column in cursor.fetchall()]

    new_columns = {
        "url": "TEXT",
        "threat_level": "TEXT",
        "risk_score": "REAL",
        "explanation": "TEXT"
    }

    for column, data_type in new_columns.items():
        if column not in columns:
            cursor.execute(
                f"ALTER TABLE detection_history ADD COLUMN {column} {data_type}"
            )

    conn.commit()
    conn.close()
    