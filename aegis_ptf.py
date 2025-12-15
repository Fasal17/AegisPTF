#!/usr/bin/env python3

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import argparse
import requests
import socket
import subprocess
import re
import os
import sys
from datetime import datetime

# ================= COLORS =================
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

def banner():
    print(f"""{C.CYAN}
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝

 AegisPTF — Advanced Single-Script Pentest Framework
{C.RESET}""")

# ================= PAYLOAD ENGINES =================
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--"
]

# ================= UTILITIES =================
def log(msg, level="INFO"):
    color = C.BLUE
    if level == "VULN": color = C.RED
    if level == "OK": color = C.GREEN
    if level == "WARN": color = C.YELLOW
    print(f"{color}[{level}] {msg}{C.RESET}")

def fetch(url, params=None):
    try:
        return requests.get(
            url,
            params=params,
            timeout=10,
            verify=False,
            headers={"User-Agent": "AegisPTF/1.0"}
        )
    except requests.exceptions.RequestException:
        return None


# ================= RECON =================
def tech_detect(url):
    r = fetch(url)
    if not r: return
    server = r.headers.get("Server", "Unknown")
    powered = r.headers.get("X-Powered-By", "Unknown")
    log(f"Server: {server}", "INFO")
    log(f"X-Powered-By: {powered}", "INFO")

def port_scan(host):
    common_ports = [21,22,80,443,3306,8080]
    log("Port scanning started", "INFO")
    for p in common_ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, p))
            log(f"Port {p} OPEN", "OK")
            s.close()
        except:
            pass

# ================= WEB TESTING =================
def check_headers(url):
    r = fetch(url)
    if not r: return
    required = ["Content-Security-Policy","X-Frame-Options","Strict-Transport-Security"]
    for h in required:
        if h not in r.headers:
            log(f"Missing security header: {h}", "VULN")
        else:
            log(f"{h} present", "OK")

def param_reflection(url):
    test = "?aegis=reflectiontest"
    r = fetch(url + test)
    if r and "reflectiontest" in r.text:
        log("Reflected parameter detected", "VULN")

def xss_scan(url):
    for p in XSS_PAYLOADS:
        r = fetch(f"{url}?xss={p}")
        if r and p in r.text:
            log(f"XSS payload reflected: {p}", "VULN")

def sqli_scan(url):
    for p in SQLI_PAYLOADS:
        r = fetch(f"{url}?id={p}")
        if r and re.search(r"sql|syntax|mysql|error", r.text, re.I):
            log(f"Possible SQL Injection with payload: {p}", "VULN")

def jwt_check(url):
    r = fetch(url)
    if r and "Authorization" in r.headers:
        if "Bearer" in r.headers.get("Authorization",""):
            log("JWT token detected", "INFO")

# ================= SECRETS =================
def js_secrets(url):
    r = fetch(url)
    if not r: return
    secrets = re.findall(r"(api_key|token|secret)[\"']?\s*[:=]\s*[\"'].*?[\"']", r.text, re.I)
    for s in secrets:
        log(f"Possible secret found: {s}", "VULN")

# ================= REPORT =================
def save_report(target, findings):
    os.makedirs(f"output/{target}", exist_ok=True)
    path = f"output/{target}/report.md"
    with open(path, "w") as f:
        f.write(f"# AegisPTF Report\n\nTarget: {target}\nDate: {datetime.now()}\n\n")
        for i in findings:
            f.write(f"- {i}\n")
    log(f"Report saved → {path}", "OK")

# ================= ENGINE =================
def main():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target", required=True)
    parser.add_argument("--nmap", action="store_true")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    host = target.replace("https://","").replace("http://","")

    log("Starting reconnaissance", "INFO")
    tech_detect(target)
    port_scan(host)

    log("Starting web tests", "INFO")
    check_headers(target)
    param_reflection(target)
    xss_scan(target)
    sqli_scan(target)
    jwt_check(target)

    log("Secrets scanning", "INFO")
    js_secrets(target)

    if args.nmap:
        log("Running nmap", "INFO")
        subprocess.run(["nmap","-sV",host])

    log("Scan completed", "OK")

if __name__ == "__main__":
    main()
