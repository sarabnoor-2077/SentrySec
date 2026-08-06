import sqlite3

conn = sqlite3.connect("sentrysec.db")

cursor = conn.cursor()

cursor.execute("SELECT * FROM scan_history")

rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()