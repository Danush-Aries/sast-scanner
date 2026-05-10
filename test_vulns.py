import os

# Creating a dummy "vulnerable" file to test the scanner
with open("vulnerable_test.py", "w") as f:
    f.write("import os\n\ndef leak():\n    API_KEY = 'sk-1234567890'\n    print(f'Key is {API_KEY}')\n\ndef inject():\n    user_input = 'ls'\n    os.system(f'echo {user_input}')\n\ndef sql_inject():\n    conn = 'dummy'\n    conn.execute(f'SELECT * FROM users WHERE id = {1}')\n")
