import sqlite3

DATABASE = "sentrysec.db"


def get_connection():
    return sqlite3.connect(DATABASE)


def initialize_database():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            filename TEXT,

            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            total_logs INTEGER,

            failed_logins INTEGER,

            successful_logins INTEGER,

            threat_count INTEGER

        )
    """)

    conn.commit()
    conn.close()


def save_scan(filename,
              total_logs,
              failed,
              success,
              threats):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (
            filename,
            total_logs,
            failed_logins,
            successful_logins,
            threat_count
        )

        VALUES
        (?, ?, ?, ?, ?)
    """,
    (
        filename,
        total_logs,
        failed,
        success,
        threats
    ))

    conn.commit()
    conn.close()


def get_history():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *

        FROM scan_history

        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows

def get_statistics():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(threat_count) FROM scan_history")
    total_threats = cursor.fetchone()[0] or 0

    cursor.execute("SELECT AVG(threat_count) FROM scan_history")
    average_threats = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE threat_count = 0
    """)
    clean_scans = cursor.fetchone()[0]

    conn.close()

    return {
        "total_scans": total_scans,
        "total_threats": total_threats,
        "average_threats": round(average_threats, 2),
        "clean_scans": clean_scans
    }