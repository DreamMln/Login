from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
#import bcrypt   #py -m pip install bcrypt
import hashlib
import os

#initliazes the app
app = Flask(__name__)
#Sets a secret key for the Flask application.
# This key is used for securing sessions and cookies.
# It should be kept secret to prevent session tampering.
app.secret_key = 'your_secret_key'

# Generate a secure random salt - before hashing
def generate_salt():
    return os.urandom(16)  # 16 bytes salt

# Hash password with PBKDF2 and salt
def hash_password(password: str, salt: bytes) -> bytes:
    # Use PBKDF2 with HMAC (SHA-256)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password

#------DB--------------------Connect to the SQLite database
# Database Connection and
# is checking if the entered username and password, salted and hashed pwd
def check_login(usernameInput, passwordInput):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Prevent SQL injection
    cursor.execute('''SELECT username, password, salt FROM users WHERE username = ?''', (usernameInput,))
    user = cursor.fetchone()
    conn.close()

    if user is None:
        print('Error! No user found')
        return False

    stored_username, stored_hashed_password, stored_salt = user

    # Hash the input password with the stored salt
    hashed_input_password = hash_password(passwordInput, stored_salt)

    # Compare the hashed password with the stored hash
    if hashed_input_password == stored_hashed_password:
        return True
    else:
        print('The password is incorrect!')
        return False

#------------------------route for the login---------------------------
#POST - When the user submits the login form, the app.py gets the username and password
# values from the form data (on index) using request.form['username'] and request.form['password'].
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        password = request.form['password']
# Check the login credentials using the check_login function
#the username is stored in the session using session['username'] = username,
        if check_login(username, password):
            session['username'] = username  # Store username in session
            return redirect(url_for('index'))  # Redirect to the main page after login
        else:
            return "Invalid username or password", 401

    # Render the index.html if GET request
    return render_template('index.html', username=session.get('username'))

#--------------------------------Route for the dashboard (if logged in)-------------
@app.route('/index')
def index():
    # Check if the user is logged in
    if 'username' in session:
        return render_template('index.html', username=session['username'])  # Render the template with username
    else:
        return redirect(url_for('login'))  # Redirect to page if not logged in
#---------------------------logout session/user-------------------------
#session.pop('username', None) removes the username key from the session,
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from the session
    return redirect(url_for('index'))  # Redirect to index page after logout

#running the flask app
if __name__ == '__main__':
    app.run(debug=True)
