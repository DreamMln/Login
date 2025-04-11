import sqlite3
import hashlib
import os

def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

# Connect to database (or create it)
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS users")  # optional fresh start
cursor.execute('''
    CREATE TABLE users (
        username TEXT PRIMARY KEY,
        password BLOB,
        salt BLOB
    )
''')

# Create and insert user 'j' with password '123'
salt = generate_salt()
hashed_pwd = hash_password('123', salt)

cursor.execute('''
    INSERT INTO users (username, password, salt) VALUES (?, ?, ?)
''', ('admin', hashed_pwd, salt))

# Commit the changes and close
conn.commit()
conn.close()
