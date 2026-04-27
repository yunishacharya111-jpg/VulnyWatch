import requests
import socket
import ssl
import urllib3
from datetime import datetime
from urllib.parse import urlparse
from html.parser import HTMLParser

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0 (VulnyWatch/1.0)"}
TIMEOUT = 8


def get_domain(url):
    return urlparse(url).netloc.split(':')[0]


def run_scan(url):
    results = []

    if not url.startswith('http'):
        url = 'https://' + url

    try:
        resp    = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                               allow_redirects=True, verify=False)
        headers = resp.headers
    except Exception as e:
        results.append(make("Connectivity", "FAIL", "CRITICAL",
            f"Could not connect to {url}: {e}",
            "A01", "Ensure the URL is correct and the site is online."))
        return results, 0, "CRITICAL"

    domain = get_domain(url)

    # A01 - Sensitive Paths
    sensitive_paths = ['/admin', '/login', '/wp-admin', '/.env',
                       '/config', '/backup', '/api/users', '/phpmyadmin']
    found_paths = []
    for path in sensitive_paths:
        try:
            r = requests.get(url.rstrip('/') + path, headers=HEADERS, timeout=5, verify=False)
            if r.status_code == 200:
                found_paths.append(path)
        except:
            pass
    if found_paths:
        results.append(make("Sensitive Paths Exposed", "FAIL", "HIGH",
            f"Accessible paths: {', '.join(found_paths)}",
            "A01", "Restrict access to admin/config paths using authentication and server rules."))
    else:
        results.append(make("Sensitive Paths Exposed", "PASS", "PASS",
            "No sensitive paths found publicly accessible.", "A01", ""))

    # A01 - Open Redirect
    try:
        redirect_params = ['redirect', 'next', 'url', 'return', 'returnUrl']
        open_redirect = False
        for param in redirect_params:
            r = requests.get(url, params={param: 'https://evil.com'},
                           headers=HEADERS, timeout=4, verify=False, allow_redirects=False)
            if r.status_code in [301, 302] and 'evil.com' in r.headers.get('Location', ''):
                open_redirect = True
                break
        if open_redirect:
            results.append(make("Open Redirect", "FAIL", "MEDIUM",
                "Open redirect vulnerability detected.",
                "A01", "Validate redirect URLs against a whitelist of allowed destinations."))
        else:
            results.append(make("Open Redirect", "PASS", "PASS",
                "No open redirect detected.", "A01", ""))
    except:
        results.append(make("Open Redirect", "PASS", "PASS",
            "No open redirect detected.", "A01", ""))

    # A02 - SSL Certificate
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert    = ssock.getpeercert()
                tls_ver = ssock.version()
        expiry_str  = cert.get('notAfter', '')
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_left   = (expiry_date - datetime.utcnow()).days
        if days_left < 0:
            results.append(make("SSL Certificate", "FAIL", "CRITICAL",
                f"Certificate EXPIRED {abs(days_left)} days ago.",
                "A02", "Renew the SSL certificate immediately."))
        elif days_left < 14:
            results.append(make("SSL Certificate", "FAIL", "HIGH",
                f"Certificate expires in {days_left} days.",
                "A02", "Renew the SSL certificate before it expires."))
        elif days_left < 30:
            results.append(make("SSL Certificate", "WARN", "MEDIUM",
                f"Certificate expires in {days_left} days.",
                "A02", "Plan to renew the SSL certificate soon."))
        else:
            results.append(make("SSL Certificate", "PASS", "PASS",
                f"Valid. Expires in {days_left} days.", "A02", ""))
        if tls_ver in ['TLSv1.3', 'TLSv1.2']:
            results.append(make("TLS Version", "PASS", "PASS", f"{tls_ver} in use.", "A02", ""))
        else:
            results.append(make("TLS Version", "FAIL", "HIGH",
                f"Outdated {tls_ver} detected.",
                "A02", "Upgrade to TLS 1.2 or TLS 1.3 on your server."))
    except Exception as e:
        results.append(make("SSL Certificate", "FAIL", "HIGH",
            f"SSL check failed: {e}", "A02", "Ensure HTTPS is properly configured."))

    if url.startswith('https://'):
        results.append(make("HTTPS Enforced", "PASS", "PASS", "Site uses HTTPS.", "A02", ""))
    else:
        results.append(make("HTTPS Enforced", "FAIL", "HIGH", "Site is not using HTTPS.",
            "A02", "Enable HTTPS and redirect all HTTP traffic to HTTPS."))

    # A03 - XSS
    xss_payload = '<script>alert(1)</script>'
    try:
        r = requests.get(url, params={'q': xss_payload}, headers=HEADERS, timeout=TIMEOUT, verify=False)
        if xss_payload in r.text:
            results.append(make("XSS (Reflected)", "FAIL", "HIGH",
                "Reflected XSS payload found in response.",
                "A03", "Sanitize and encode all user-supplied input before outputting to HTML."))
        else:
            results.append(make("XSS (Reflected)", "PASS", "PASS", "No reflected XSS detected.", "A03", ""))
    except:
        results.append(make("XSS (Reflected)", "SKIP", "INFO", "Could not test.", "A03", ""))

    # A03 - SQL Injection
    sql_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users;--"]
    error_signs  = ["sql syntax", "mysql_fetch", "unclosed quotation", "odbc driver", "ora-0", "sqlite_"]
    sql_found = False
    for payload in sql_payloads:
        try:
            r = requests.get(url, params={'id': payload}, headers=HEADERS, timeout=TIMEOUT, verify=False)
            for sign in error_signs:
                if sign in r.text.lower():
                    sql_found = True
                    break
        except:
            pass
        if sql_found:
            break
    if sql_found:
        results.append(make("SQL Injection", "FAIL", "CRITICAL",
            "SQL error messages detected in response.",
            "A03", "Use parameterised queries. Never concatenate user input into SQL."))
    else:
        results.append(make("SQL Injection", "PASS", "PASS",
            "No SQL injection indicators found.", "A03", ""))

    # A04 - Rate Limiting
    try:
        login_url = url.rstrip('/') + '/login'
        test_data = {'username': 'test', 'password': 'test', 'email': 'test@test.com'}
        responses = []
        for _ in range(5):
            r = requests.post(login_url, data=test_data, headers=HEADERS, timeout=5, verify=False)
            responses.append(r.status_code)
        if all(c == responses[0] for c in responses):
            results.append(make("Rate Limiting", "FAIL", "MEDIUM",
                "No rate limiting detected on login endpoint.",
                "A04", "Implement rate limiting and account lockout after failed attempts."))
        else:
            results.append(make("Rate Limiting", "PASS", "PASS",
                "Rate limiting appears to be in place.", "A04", ""))
    except:
        results.append(make("Rate Limiting", "SKIP", "INFO", "Could not test rate limiting.", "A04", ""))

    # A05 - Security Headers
    sec_headers = {
        "Content-Security-Policy":   ("CRITICAL", "Add a Content-Security-Policy header to prevent XSS."),
        "X-Frame-Options":           ("LOW",      "Add X-Frame-Options: DENY to prevent clickjacking."),
        "X-Content-Type-Options":    ("MEDIUM",   "Add X-Content-Type-Options: nosniff."),
        "Strict-Transport-Security": ("HIGH",     "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        "Referrer-Policy":           ("INFO",     "Add Referrer-Policy: no-referrer-when-downgrade."),
        "Permissions-Policy":        ("INFO",     "Add Permissions-Policy to control browser feature access."),
    }
    for h, (sev, fix) in sec_headers.items():
        if h in headers:
            results.append(make(f"Header: {h}", "PASS", "PASS", f"{h} is set.", "A05", ""))
        else:
            results.append(make(f"Header: {h}", "FAIL", sev, f"{h} is missing.", "A05", fix))

    server = headers.get('Server', '')
    if server:
        results.append(make("Server Info Disclosure", "WARN", "LOW",
            f"Server header reveals: {server}",
            "A05", "Remove or obscure the Server header in your web server config."))
    else:
        results.append(make("Server Info Disclosure", "PASS", "PASS",
            "Server header not exposed.", "A05", ""))

    # A05 - CORS
    try:
        r = requests.get(url, headers={**HEADERS, 'Origin': 'https://evil.com'}, timeout=TIMEOUT, verify=False)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or acao == 'https://evil.com':
            results.append(make("CORS Policy", "FAIL", "HIGH",
                f"Overly permissive CORS: Access-Control-Allow-Origin: {acao}",
                "A05", "Restrict CORS to trusted domains only."))
        else:
            results.append(make("CORS Policy", "PASS", "PASS",
                "CORS policy appears properly configured.", "A05", ""))
    except:
        results.append(make("CORS Policy", "SKIP", "INFO", "Could not test CORS.", "A05", ""))

    # A05 - Open Risky Ports
    risky_ports = {21: "FTP", 23: "Telnet", 3306: "MySQL",
                   5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
    open_risky = []
    for port, name in risky_ports.items():
        try:
            s = socket.create_connection((domain, port), timeout=2)
            s.close()
            open_risky.append(f"{name}({port})")
        except:
            pass
    if open_risky:
        results.append(make("Open Risky Ports", "FAIL", "HIGH",
            f"Open ports: {', '.join(open_risky)}",
            "A05", "Close unnecessary ports. Database ports should never be public."))
    else:
        results.append(make("Open Risky Ports", "PASS", "PASS",
            "No risky ports found open.", "A05", ""))

    # A06 - Technology Disclosure
    powered = headers.get('X-Powered-By', '')
    if powered:
        results.append(make("Technology Disclosure", "WARN", "LOW",
            f"X-Powered-By: {powered}",
            "A06", "Remove the X-Powered-By header to avoid revealing technology stack."))
    else:
        results.append(make("Technology Disclosure", "PASS", "PASS",
            "X-Powered-By header not exposed.", "A06", ""))

    # A07 - Cookie Security
    raw_cookies = resp.headers.get('Set-Cookie', '')
    if raw_cookies:
        issues = []
        if 'secure' not in raw_cookies.lower():
            issues.append("missing Secure flag")
        if 'httponly' not in raw_cookies.lower():
            issues.append("missing HttpOnly flag")
        if 'samesite' not in raw_cookies.lower():
            issues.append("missing SameSite attribute")
        if issues:
            results.append(make("Cookie Security", "FAIL", "MEDIUM",
                f"Cookie issues: {', '.join(issues)}",
                "A07", "Set Secure, HttpOnly, and SameSite=Strict on all session cookies."))
        else:
            results.append(make("Cookie Security", "PASS", "PASS",
                "All cookies have proper security flags.", "A07", ""))
    else:
        results.append(make("Cookie Security", "SKIP", "INFO", "No cookies found.", "A07", ""))

    # A08 - Subresource Integrity
    try:
        class ScriptParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.issues = []
            def handle_starttag(self, tag, attrs):
                if tag == 'script':
                    attrs_dict = dict(attrs)
                    src = attrs_dict.get('src', '')
                    if src and ('cdn' in src or 'ajax' in src or 'cloudflare' in src):
                        if 'integrity' not in attrs_dict:
                            self.issues.append(src)
        parser = ScriptParser()
        parser.feed(resp.text)
        if parser.issues:
            results.append(make("Subresource Integrity", "FAIL", "MEDIUM",
                f"CDN scripts missing integrity attribute: {len(parser.issues)} found.",
                "A08", "Add integrity and crossorigin attributes to all external scripts."))
        else:
            results.append(make("Subresource Integrity", "PASS", "PASS",
                "No CDN scripts missing integrity checks.", "A08", ""))
    except:
        results.append(make("Subresource Integrity", "SKIP", "INFO",
            "Could not check subresource integrity.", "A08", ""))

    # A09 - robots.txt
    try:
        r = requests.get(url.rstrip('/') + '/robots.txt', headers=HEADERS, timeout=TIMEOUT, verify=False)
        sensitive = ['/admin', '/backup', '/config', '/.env', '/private']
        exposed   = [p for p in sensitive if p in r.text]
        if exposed:
            results.append(make("robots.txt Disclosure", "WARN", "LOW",
                f"Sensitive paths in robots.txt: {', '.join(exposed)}",
                "A09", "Remove sensitive paths from robots.txt — it advertises them to attackers."))
        else:
            results.append(make("robots.txt Disclosure", "PASS", "PASS",
                "No sensitive paths found in robots.txt.", "A09", ""))
    except:
        results.append(make("robots.txt Disclosure", "SKIP", "INFO",
            "robots.txt not found.", "A09", ""))

    # A10 - SSRF
    try:
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'next', 'target']
        ssrf_found = False
        for param in ssrf_params:
            r = requests.get(url, params={param: 'http://169.254.169.254/'},
                           headers=HEADERS, timeout=4, verify=False)
            if r.status_code == 200 and 'ami-id' in r.text.lower():
                ssrf_found = True
                break
        if ssrf_found:
            results.append(make("SSRF Vulnerability", "FAIL", "CRITICAL",
                "Possible SSRF — internal metadata accessible.",
                "A10", "Validate and whitelist all URLs accepted as user input."))
        else:
            results.append(make("SSRF Vulnerability", "PASS", "PASS",
                "No SSRF indicators found.", "A10", ""))
    except:
        results.append(make("SSRF Vulnerability", "PASS", "PASS",
            "No SSRF indicators found.", "A10", ""))

    score, label = calculate_score(results)
    return results, score, label


def make(check_name, status, severity, detail, owasp, fix):
    return {
        "check_name": check_name,
        "status":     status,
        "severity":   severity,
        "detail":     detail,
        "owasp":      owasp,
        "fix":        fix
    }


def calculate_score(results):
    weights = {
        "CRITICAL": 0.0, "HIGH": 0.3, "MEDIUM": 0.6,
        "LOW": 0.85,     "INFO": 1.0, "PASS":  1.0, "SKIP": 0.9
    }
    total, earned = 0, 0
    for r in results:
        sev = r['severity']
        if sev in weights:
            total  += 1
            earned += 1.0 if r['status'] == 'PASS' else weights.get(sev, 0.5)

    score = round((earned / total) * 100) if total > 0 else 0

    if score >= 90:   label = "SECURE"
    elif score >= 75: label = "LOW"
    elif score >= 60: label = "MEDIUM"
    elif score >= 40: label = "HIGH"
    else:             label = "CRITICAL"

    return score, label