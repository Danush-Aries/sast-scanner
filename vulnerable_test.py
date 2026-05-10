import os

def leak():
    API_KEY = 'sk-1234567890'
    print(f'Key is {API_KEY}')

def inject():
    user_input = 'ls'
    os.system(f'echo {user_input}')

def sql_inject():
    conn = 'dummy'
    conn.execute(f'SELECT * FROM users WHERE id = {1}')
