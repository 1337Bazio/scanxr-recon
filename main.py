import requests
import socket
import ssl
import re
import json
import sys
import time
import random
import getpass

from urllib.parse import urlparse, urljoin

# =========================
# ACCESS KEY
# =========================

ACCESS_KEY = "1337"

def check_key():
    print("\n=== AUTH REQUIRED ===")
    key = input("Enter access key: ").strip()

    if key != ACCESS_KEY:
        print("\n[ERROR] Invalid key. Access denied.")
        sys.exit(0)

    print("\n[OK] Access granted.\n")

# =========================
# REQUESTS
# =========================

requests.packages.urllib3.disable_warnings()

session = requests.Session()

session.headers.update({
    "User-Agent": "BAZIO-RECON/4.0"
})

# =========================
# CONFIG
# =========================

PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/HEAD",
    "/admin",
    "/login",
    "/api",
    "/graphql",
    "/swagger.json",
    "/backup",
    "/debug",
    "/.DS_Store"
]

PARAMS = [
    "id","user","page","q",
    "search","file","redirect",
    "url","token","action"
]

IDOR_PARAMS = [
    "id","user","uid",
    "account","profile",
    "order","item","file"
]

# =========================
# VULN DATABASE
# =========================

VULN_INFO = {

    "idor": {
        "name": "Insecure Direct Object Reference",
        "severity": "HIGH",
        "description": "The application may expose internal objects without proper authorization checks.",
        "impact": "Attackers could access data belonging to other users.",
        "reference": "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet",
        "cwe": "CWE-639",
        "fix": "Implement proper server-side authorization checks."
    },

    "headers": {
        "name": "Missing Security Headers",
        "severity": "MEDIUM",
        "description": "Important HTTP security headers are missing.",
        "impact": "Can increase exposure to XSS, clickjacking, or MIME attacks.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "cwe": "CWE-693",
        "fix": "Add recommended HTTP security headers."
    },

    "js": {
        "name": "Sensitive Information Exposure",
        "severity": "MEDIUM",
        "description": "JavaScript files may expose secrets, endpoints, or internal logic.",
        "impact": "Attackers could discover hidden APIs or sensitive tokens.",
        "reference": "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
        "cwe": "CWE-200",
        "fix": "Remove secrets and sensitive endpoints from frontend files."
    },

    "auth": {
        "name": "Authentication Surface Exposure",
        "severity": "LOW",
        "description": "Authentication-related endpoints were identified.",
        "impact": "May help attackers enumerate authentication mechanisms.",
        "reference": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "cwe": "CWE-306",
        "fix": "Reduce unnecessary authentication surface exposure."
    },

    "paths": {
        "name": "Sensitive Path Exposure",
        "severity": "MEDIUM",
        "description": "Sensitive files or endpoints may be publicly accessible.",
        "impact": "Could expose internal configuration or debugging information.",
        "reference": "https://owasp.org/www-project-top-ten/",
        "cwe": "CWE-548",
        "fix": "Restrict access to internal files and sensitive endpoints."
    }
}

# =========================
# UI
# =========================

def banner():

    print("="*70)

    print(r"""                                              
  ______ ____ _____    ____ ___  __________ 
 /  ___// ___\\__  \  /    \\  \/  /\_  __ \
 \___ \\  \___ / __ \|   |  \>    <  |  | \/
/____  >\___  >____  /___|  /__/\_ \ |__|   
     \/     \/     \/     \/      \/        
""")

    print(" by bazio          ScanXr RECON TOOL v4.0 ")
    print("="*70)
    print()

def matrix(msg):

    for c in msg:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(random.uniform(0.001,0.005))

    print()

def status(msg):
    print(f"[INFO] {msg}")

# =========================
# CORE
# =========================

def norm(u):
    return u if u.startswith("http") else "http://" + u

def join(a,b):
    return urljoin(a,b)

def req(url):

    try:

        return session.get(
            url,
            timeout=5,
            verify=False,
            allow_redirects=True
        )

    except:
        return None

# =========================
# TITLE
# =========================

def get_site_name(html, domain):

    if not html:
        return domain

    m = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.I | re.S
    )

    if not m:
        return domain

    title = re.sub(r"\s+"," ",m.group(1)).strip()

    return title[:100]

# =========================
# IP
# =========================

def get_ip(domain):

    try:
        return socket.gethostbyname(domain)
    except:
        return None

# =========================
# SSL
# =========================

def ssl_info(domain):

    try:

        ctx = ssl.create_default_context()

        s = ctx.wrap_socket(
            socket.socket(),
            server_hostname=domain
        )

        s.settimeout(3)

        s.connect((domain,443))

        c = s.getpeercert()

        return {
            "issuer": c.get("issuer"),
            "expiry": c.get("notAfter")
        }

    except:
        return None

# =========================
# COOKIES
# =========================

def parse_cookies(cookies):

    out = []

    for c in cookies:

        out.append({
            "name": c.name,
            "value": c.value,
            "secure": c.secure,
            "httponly": "HttpOnly" in str(c._rest)
        })

    return out

# =========================
# FINDINGS
# =========================

def finding(t, src, details):

    info = VULN_INFO.get(t, {})

    return {
        "type": t,
        "name": info.get("name"),
        "severity": info.get("severity"),
        "source": src,
        "details": details,
        "description": info.get("description"),
        "impact": info.get("impact"),
        "reference": info.get("reference"),
        "cwe": info.get("cwe"),
        "fix": info.get("fix")
    }

# =========================
# TECH DETECTION
# =========================

def tech_detect(html, headers):

    h = html.lower()

    out = []

    if "react" in h:
        out.append("React")

    if "vue" in h:
        out.append("Vue")

    if "angular" in h:
        out.append("Angular")

    if "laravel" in h:
        out.append("Laravel")

    if "wordpress" in h:
        out.append("WordPress")

    if "nginx" in str(headers).lower():
        out.append("Nginx")

    if "apache" in str(headers).lower():
        out.append("Apache")

    return list(set(out))

# =========================
# SECURITY HEADERS
# =========================

def security_headers(headers):

    checks = {
        "Content-Security-Policy": "CSP missing",
        "X-Frame-Options": "Clickjacking protection missing",
        "X-Content-Type-Options": "MIME sniffing protection missing",
        "Strict-Transport-Security": "HSTS missing",
        "Referrer-Policy": "Referrer policy missing"
    }

    findings = []

    for h,msg in checks.items():

        if h not in headers:
            findings.append(msg)

    return findings

# =========================
# AUTH
# =========================

def auth_surface(html):

    h = html.lower()

    out = []

    if "login" in h:
        out.append("login detected")

    if "logout" in h:
        out.append("logout detected")

    if "reset" in h:
        out.append("password reset")

    return out

# =========================
# PARAM TEST
# =========================

def param_test(base):

    hits = []

    for p in PARAMS:

        r = req(f"{base}?{p}=TESTX")

        if r and "TESTX" in r.text:
            hits.append(p)

    return hits

# =========================
# PATH ENUM
# =========================

def path_test(base):

    found = []

    for p in PATHS:

        r = req(join(base,p))

        if r and r.status_code < 500:

            found.append({
                "path": p,
                "status": r.status_code
            })

    return found

# =========================
# JS EXTRACTION
# =========================

def js_extract(html):

    return list(set(
        re.findall(
            r'src=["\'](.*?\.js)["\']',
            html
        )
    ))

# =========================
# API EXTRACTION
# =========================

def extract_endpoints(js_text):

    regex = r'["\'](\/api\/.*?|https?:\/\/.*?\/api\/.*?)["\']'

    return list(set(
        re.findall(regex, js_text)
    ))

# =========================
# JS ANALYSIS
# =========================

def js_analyze(url):

    print(f"[JS] {url}")

    r = req(url)

    if not r:
        return []

    t = r.text.lower()

    out = []

    if "apikey" in t or "secret" in t:
        out.append("possible secret leak")

    if "graphql" in t:
        out.append("graphql detected")

    if "ws://" in t or "wss://" in t:
        out.append("websocket endpoint")

    if ".map" in t:
        out.append("source map exposed")

    endpoints = extract_endpoints(r.text)

    for ep in endpoints[:20]:
        out.append(f"api endpoint: {ep}")

    return out

# =========================
# IDOR
# =========================

def idor_test(base):

    findings = []

    for p in IDOR_PARAMS:

        r1 = req(f"{base}?{p}=1")

        if not r1:
            continue

        baseline = r1.text
        baseline_len = len(r1.text)
        baseline_code = r1.status_code

        for val in ["2","3","10","9999"]:

            r2 = req(f"{base}?{p}={val}")

            if not r2:
                continue

            if r2.status_code == 200 and r2.text != baseline:

                findings.append({
                    "param": p,
                    "value": val,
                    "reason": "response variation",
                    "status": r2.status_code
                })

            elif r2.status_code == 200 and abs(len(r2.text)-baseline_len) > 200:

                findings.append({
                    "param": p,
                    "value": val,
                    "reason": "size anomaly",
                    "status": r2.status_code
                })

            elif baseline_code == 403 and r2.status_code == 200:

                findings.append({
                    "param": p,
                    "value": val,
                    "reason": "possible access bypass",
                    "status": r2.status_code
                })

    return findings

# =========================
# SCORE
# =========================

def score(data):

    s = 100

    s -= len(data.get("params",[]))*5
    s -= len(data.get("paths",[]))*2
    s -= len(data.get("findings",[]))*4
    s -= len(data.get("cookies",[]))*2
    s -= len(data.get("js",[]))*1
    s -= len(data.get("idor",[]))*10

    return max(0, round(s,2))

def classify(score):

    if score >= 80:
        return "LOW RISK"

    elif score >= 50:
        return "MEDIUM RISK"

    return "HIGH RISK"

# =========================
# ENGINE
# =========================

class Engine:

    def __init__(self,target):

        self.target = norm(target)

        self.domain = urlparse(
            self.target
        ).netloc

        self.data = {
            "url": self.target,
            "domain": self.domain,
            "ip": None,
            "cookies": [],
            "js": [],
            "paths": [],
            "params": [],
            "idor": [],
            "tech": [],
            "ssl": None,
            "findings": [],
            "score": 0
        }

    def add(self,f):
        self.data["findings"].append(f)

# =========================
# DISPLAY FINDINGS
# =========================

def print_finding(f):

    print("\n" + "-"*70)

    print(f"[{f['severity']}] {f['name']}")

    print(f"\nTarget:")
    print(f"{f['source']}")

    print(f"\nDetails:")
    print(f"{f['details']}")

    print(f"\nDescription:")
    print(f"{f['description']}")

    print(f"\nImpact:")
    print(f"{f['impact']}")

    print(f"\nCWE:")
    print(f"{f['cwe']}")

    print(f"\nReference:")
    print(f"{f['reference']}")

    print(f"\nRecommendation:")
    print(f"{f['fix']}")

# =========================
# SUMMARY
# =========================

def summary(data):

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    print(f"\nTarget:")
    print(data["url"])

    print(f"\nIP:")
    print(data["ip"])

    print(f"\nRisk:")
    print(f"{data['score']}/100")

    print(f"\nTech:")
    if data["tech"]:
        for t in data["tech"]:
            print(f" - {t}")
    else:
        print(" None")

    print(f"\nReflected Params:")
    if data["params"]:
        for p in data["params"]:
            print(f" - {data['url']}?{p}=TESTX")
    else:
        print(" None")

    print(f"\nAccessible Paths:")
    if data["paths"]:
        for p in data["paths"]:
            print(f" - {data['url'].rstrip('/')}{p['path']} [{p['status']}]")
    else:
        print(" None")

    print(f"\nJavaScript Files:")
    if data["js"]:
        for j in data["js"]:
            print(f" - {join(data['url'], j)}")
    else:
        print(" None")

    print(f"\nPossible IDOR:")
    if data["idor"]:
        for i in data["idor"]:
            print(
                f" - {data['url']}?"
                f"{i['param']}={i['value']} "
                f"({i['reason']})"
            )
    else:
        print(" None")

    print(f"\nCookies:")
    if data["cookies"]:
        for c in data["cookies"]:
            print(f" - {c['name']}")
    else:
        print(" None")

# =========================
# SCAN
# =========================

def scan(target):

    start = time.time()

    e = Engine(target)

    matrix("[+] Initializing BAZIO engine...")

    status("Connecting to target...")

    r = req(e.target)

    if not r:
        print("[ERROR] Target unreachable")
        return None

    html = r.text

    site_name = get_site_name(
        html,
        e.domain
    )

    print(f"\nTARGET: {site_name}")

    status("Resolving IP...")
    e.data["ip"] = get_ip(e.domain)

    status("Extracting cookies...")
    e.data["cookies"] = parse_cookies(r.cookies)

    status("Analyzing auth surface...")

    for i in auth_surface(html):

        e.add(finding(
            "auth",
            e.target,
            i
        ))

    status("Checking security headers...")

    for h in security_headers(r.headers):

        e.add(finding(
            "headers",
            e.target,
            h
        ))

    status("Testing reflected parameters...")

    e.data["params"] = param_test(
        e.target
    )

    status("Enumerating paths...")

    e.data["paths"] = path_test(
        e.target
    )

    for p in e.data["paths"]:

        e.add(finding(
            "paths",
            e.target,
            f"Accessible path: {p['path']} (HTTP {p['status']})"
        ))

    status("Analyzing JavaScript files...")

    js = js_extract(html)

    e.data["js"] = js

    for j in js[:10]:

        full = join(e.target,j)

        for f in js_analyze(full):

            e.add(finding(
                "js",
                full,
                f
            ))

    status("Testing IDOR patterns...")

    idor = idor_test(e.target)

    e.data["idor"] = idor

    for i in idor:

        e.add(finding(
            "idor",
            e.target,
            f"Possible IDOR detected on parameter '{i['param']}' with value '{i['value']}' ({i['reason']})"
        ))

    status("Detecting technologies...")

    e.data["tech"] = tech_detect(
        html,
        r.headers
    )

    status("Checking SSL certificate...")

    e.data["ssl"] = ssl_info(
        e.domain
    )

    e.data["score"] = score(
        e.data
    )

    elapsed = round(
        time.time() - start,
        2
    )

    print("\n" + "="*70)
    print("BAZIO SCAN RESULTS")
    print("="*70)

    print(f"\nDomain: {e.data['domain']}")
    print(f"IP: {e.data['ip']}")
    print(f"Risk Score: {e.data['score']}/100")
    print(f"Classification: {classify(e.data['score'])}")

    if e.data["tech"]:

        print("\nTechnologies:")

        for t in e.data["tech"]:
            print(f" - {t}")

    if e.data["cookies"]:

        print("\nCookies:")

        for c in e.data["cookies"]:

            print(
                f" - {c['name']} "
                f"(Secure={c['secure']} "
                f"HttpOnly={c['httponly']})"
            )

    if e.data["findings"]:

        print("\n" + "="*70)
        print("DETAILED FINDINGS")
        print("="*70)

        for f in e.data["findings"]:
            print_finding(f)

    print("\n" + "="*70)
    print(f"Scan completed in {elapsed} seconds")

    with open("result.json","w") as f:
        json.dump(e.data,f,indent=2)

    print("Results exported to result.json")

    print("\n" + "="*70)
    print("RAW JSON")
    print("="*70)

    print(json.dumps(
        e.data,
        indent=2
    ))

    return e

# =========================
# ENTRY
# =========================

if __name__ == "__main__":

    banner()

    check_key()

    target = input("TARGET URL: ")

    engine = None

    try:

        engine = scan(target)

    except KeyboardInterrupt:

        print("\n[INFO] Interrupted by user")

    except Exception as ex:

        print(f"\n[ERROR] {ex}")

    while True:

        print("\n" + "="*70)
        print("[1] Summary")
        print("[2] Exit")
        print("="*70)

        choice = input("\nChoice: ").strip()

        if choice == "1":

            if engine and engine.data:

                summary(engine.data)

            else:

                print("\nNo scan data available.")

        elif choice == "2":

            print("\nBAZIO closed.")
            break

        else:

            print("\nInvalid choice.")

    input("\nPress ENTER to quit...")
