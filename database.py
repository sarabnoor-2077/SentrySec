import sqlite3

DATABASE = "sentrysec.db"


def get_connection():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn


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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_details (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        scan_id INTEGER,

        severity TEXT,

        message TEXT,

        ip_address TEXT,

        log_time TEXT,

        FOREIGN KEY(scan_id)
            REFERENCES scan_history(id)

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

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return scan_id

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

def get_chart_data():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, threat_count
        FROM scan_history
        ORDER BY id
    """)

    rows = cursor.fetchall()

    conn.close()

    labels = []
    threats = []

    for row in rows:
        labels.append(f"Scan {row['id']}")
        threats.append(row["threat_count"])

    return labels, threats

def get_scan(scan_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scan_history
        WHERE id = ?
    """, (scan_id,))

    scan = cursor.fetchone()

    conn.close()

    return scan


def get_threats(scan_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM threat_details
        WHERE scan_id = ?
        ORDER BY id
    """, (scan_id,))

    threats = cursor.fetchall()

    conn.close()

    return threats

def save_threat(scan_id, severity, message, ip_address, log_time):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO threat_details
        (
            scan_id,
            severity,
            message,
            ip_address,
            log_time
        )

        VALUES
        (?, ?, ?, ?, ?)
    """,
    (
        scan_id,
        severity,
        message,
        ip_address,
        log_time
    ))

    conn.commit()

    conn.close()