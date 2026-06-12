# Sample file used as a scan fixture — intentionally vulnerable for demo purposes.
# DO NOT use patterns like this in production code.

import os
import sqlite3

# Command injection via f-string
user = "admin"
os.system(f"echo {user}")

# SQL injection via f-string
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
user_id = 1
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
