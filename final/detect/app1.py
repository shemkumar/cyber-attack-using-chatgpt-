from flask import Flask, request, render_template
import re
import pandas as pd

app = Flask(__name__)

# Define patterns for detecting attacks without using look-behind assertions
patterns = {
    'SQL Injection': r"(union(\s+all)?\s+select|select\s+.*\s+from|drop\s+table|insert\s+into)",
    'Brute Force (Repeated Requests)': r'(GET\s|POST\s)[^ ]*\s+\d+(\.\d+){3}.*',
    'Suspicious User-Agent': r"curl|wget|python|libwww|java|nmap",
    'Large Request Size': r"\s[4-9][0-9]{3,}\s",
    'HTTP Error 500': r'HTTP/1.[01]" 500',
    'Cross-Site Scripting (XSS)': r"<script>|</script>|alert\(.*\)|onerror=|onload=|document\.cookie|eval\(|window\.location|location\.replace\(",
    'Command Injection': r";|&&|\|\||\$(.*)|bash|sh|cmd|wget\s+.*\s+http",
    'Local File Inclusion (LFI)': r"\.\./|\.\.\\|/etc/passwd|/proc/self/environ|/var/www/html|file://|php://input",
    'Remote File Inclusion (RFI)': r"http://|ftp://|file://|include\(.*\)|require\(.*\)|eval\(file_get_contents\(.*\)\)",
    'Denial of Service (DoS)': r"GET\s*\/\s*HTTP/1.1|POST\s*\/\s*HTTP/1.1|multiple\s+requests\s+from\s+same\s+IP|excessive\s+request\s+rate",
    'Distributed Denial of Service (DDoS)': r"multiple\s+requests\s+from\s+different\s+IP\s+addresses|flood\s+of\s+GET\s+requests|flood\s+of\s+POST\s+requests|TCP\s+SYN\s+flood|UDP\s+flood|HTTP\s+flood",
    'Suspicious HTTP Methods': r"PUT\s*\/|DELETE\s*\/|PATCH\s*\/|TRACE\s*\/|CONNECT\s*\/|OPTIONS\s*\/|HEAD\s*\/|MOVE\s*\/|COPY\s*\/|PROPFIND\s*\/",
    'Path Traversal': r"\.\./|\.\.\\|\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ|\/var\/www\/html|\/bin\/bash|%2e%2e%2f|%2e%2e%5c|%2e%2e%2e%2f",
    'Suspicious User-Agent': r"curl|wget|python|libwww|java|nmap|bot|spider|crawler",
    'PHP Injection': r"php:\/\/input|eval\(.*\)|base64_decode\(.*\)",
    'Shell Injection': r"bash\s+-c|sh\s+-c|cmd\s+/c",
    'SQL Error Message': r"SQL\s+syntax\s+.*MySQL|SQLSTATE|MySQL\s+error|Warning:.*mysql_fetch|Warning:.*mysqli_fetch|error\s+in\s+your\s+SQL\s+syntax",
    'XML External Entity (XXE)': r"<!ENTITY\s+.*SYSTEM\s+\"file:\/\/.*\"|<!DOCTYPE\s+.*\s+SYSTEM\s+\"file:\/\/.*\"",
    'Reverse Shell': r"bash\s+-i\s+>&amp;\s+|bash\s+-i\s+<\/dev\/tcp\/.*\s+\|\s+sh\s+-i",
    'Sensitive File Access': r"/etc/passwd|/etc/shadow|/proc/self/environ|/var/www/html/.env",
    'PHP Shell Upload': r"\.php$|\.php3$|\.php5$|\.phtml$|\.asp$|\.jsp$|\.exe$",
    'Request Smuggling': r"Transfer-Encoding\s*:\s*chunked|Content-Length\s*:\s*\d+\s+Transfer-Encoding\s*:\s*chunked",
    'Log Injection': r"[\r\n]+.*\|.*\|.*|.*\|.*\|\s*",
    'X-Forwarded-For Header Manipulation': r"X-Forwarded-For\s*:\s*[\d\.]+|X-Real-IP\s*:\s*[\d\.]+",
    'HTTP Response Splitting': r"HTTP\/1\.[01]\s*[\d]{3}\s+[^\r\n]+\r\n\r\n",
    'Buffer Overflow': r".{10000,}",  # Long strings of data
    'Invalid HTTP Headers': r"Host\s*:\s*[\d\.]+|Content-Length\s*:\s*[\d]+|User-Agent\s*:\s*[\w\s]+|Connection\s*:\s*close",
    'Session Fixation': r"PHPSESSID\s*=\s*[\w-]+",
    'Email Injection': r"To\s*=\s*|Bcc\s*=\s*|Cc\s*=\s*|Content-Type\s*=\s*|MIME-Version\s*=\s*",
    'Open Redirect': r"href\s*=\s*\"http:\/\/.*\"|href\s*=\s*\"https:\/\/.*\"",
    'Cross-Site Request Forgery (CSRF)': r"Referer\s*:\s*[^ ]*|X-CSRF-Token|csrf_token",
    'Session Hijacking': r"JSESSIONID\s*=\s*[^ ]*|sid\s*=\s*[^ ]*",
    'Malicious File Upload': r"Content-Disposition\s*:\s*attachment\s*filename.*\.(exe|php|jsp|asp|cgi|pl|bat|sh)",
    'Command Execution (Web Shell)': r"system\(.*\)|exec\(.*\)|passthru\(.*\)|shell_exec\(.*\)",
    'RCE (Remote Code Execution)': r"eval\(.*\)|system\(.*\)|shell_exec\(.*\)",
    'Database Dump': r"mysqldump\s+.*\s+\|.*\.sql|.*\|.*\.sql$",
    'Suspicious Post Data': r"post\s+.*\s+method|POST\s+/.*\?[^ ]*|POST\s*.*\s*200",
    'Reverse Proxy Detection': r"X-Forwarded-For\s*:\s*[\d\.]+|X-Real-IP\s*:\s*[\d\.]+",
    'User-Agent Spoofing': r"Mozilla\/5\.0\s\(.*\)\sChrome\s*\/\s.*\sSafari\s*\/\s.*",
    'Web Application Firewall (WAF) Evasion': r"base64_decode\(.*\)|gzinflate\(.*\)|eval\(.*\)",
    'HTTP Host Header Attack': r"Host\s*:\s*[^ ]*|Host\s*:\s*localhost|Host\s*:\s*127\.0\.0\.1",
    'Exploit Kit Activity': r"Exploit\s+Kit|Blackhat\s+Kit|Redkit|Angler\s+Exploit\s+Kit",
    'Shellshock': r"(){}:.\/|bash\s+-c",
    'WebDAV Attack': r"PROPFIND\s*\/|COPY\s*\/|MOVE\s*\/|LOCK\s*\/|UNLOCK\s*\/",
    'SSL/TLS Attacks': r"SSLv2|SSLv3|TLSv1.0|RC4\s+cipher|NULL\s+cipher",
    'Outdated CMS Detection': r"wp-content\s+\/.*|joomla\.php|drupal\.php",
    'Clickjacking': r"<iframe|<object|<embed|<button|<input\s+type=\"button\"",
    'Sudo Command Injection': r"sudo\s+-u\s+\S+\s+.*|sudo\s+.*\s+|.*\s+sudo\s+.*",
    'Log File Poisoning': r"(?i)python.*socket.*os.*sys.*subprocess",
    'Stealthy Network Scanning': r"nmap\s+.*|masscan\s+.*|zmap\s+.*|fping\s+.*",
    'DNS Amplification Attack': r"src\s*=\s*.*\s+DNS\s+query",
    'SMTP Exploitation': r"MAIL\s+FROM\s*:<.*@.*>|RCPT\s+TO\s*:<.*@.*>",
    'Phishing Attack': r"login\s*form|email\s*address\s*validation|username\s*password",
    'Invalid SQL Syntax': r"SQL\s+syntax\s+.*MySQL|SQLSTATE|MySQL\s+error",
    'Click Fraud': r"google\s+ad\s+request|adclick\s+.*\?",
    'Credential Stuffing': r"password\s*=\s*.*|login\s+attempt|failed\s+login\s+attempt",
    'Botnet C2 Communication': r"GET\s+\/.*\s+HTTP\/1.1|POST\s+\/.*\s+HTTP\/1.1|User-Agent\s*:\s*bot",
    'Spoofed IP Address': r"X-Forwarded-For\s*:\s*[\d\.]+|X-Real-IP\s*:\s*[\d\.]+",
    'BadBot Detection': r"googlebot|bingbot|slurp|baiduspider",
    'Malicious JavaScript': r"eval\(.*\)|setTimeout\(.*\)",
    'Zero-Day Exploit': r"security\s+patch\s+available|CVE-\d{4}-\d{4,6}",
    'Mass Emailing': r"Content-Type\s*:\s*text\/html|MIME-Version\s*:\s*1.0",
    'Misconfigured Permissions': r"chmod\s+\d{3,4}|chown\s+.*|setfacl\s+.*",
    'Suspicious File Type': r".*(\.exe|\.bat|\.msi|\.js|\.vbs|\.php|\.jsp|\.asp|\.phtml|\.cgi)$",
    'FTP Brute Force': r"USER\s+.*\s+PASS\s+.*",
    'HTTP Method Tampering': r"POST\s+.*\s+HTTP/1.1|PUT\s+.*\s+HTTP/1.1|DELETE\s+.*\s+HTTP/1.1",
}



# Home route
@app.route('/')
def index():
    return render_template('mal.html')  # Main upload form

# Upload and process log file
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    # Read the log file
    logs = file.readlines()

    # Store suspicious logs
    suspicious_logs = []

    # Check for suspicious patterns
    for log in logs:
        log = log.decode('utf-8').strip()  # Ensure proper decoding
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, log, re.IGNORECASE):
                suspicious_logs.append({
                    'log': log,
                    'attack_type': pattern_name
                })

    # Render the result page with detected suspicious logs
    if suspicious_logs:
        return render_template('result.html', suspicious_logs=suspicious_logs)
    else:
        return render_template('result.html', message="No suspicious activity detected.")

if __name__ == '__main__':
    app.run(debug=True, port=2002)
