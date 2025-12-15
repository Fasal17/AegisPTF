#!/usr/bin/env python3
import argparse, asyncio, aiohttp, socket, re, os, subprocess, requests
from urllib.parse import urljoin
from datetime import datetime

OUTPUT_DIR = "output"
TIMEOUT = 12

# ================== CVSS ENGINE ==================
def cvss_severity(score):
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"

# ================== AI RISK ENGINE ==================
def ai_risk_score(v):
    score = v["cvss"]
    if "key" in v["name"].lower() or "token" in v["name"].lower():
        score += 2.5
    if "apache" in v["name"].lower() or "rce" in v["impact"].lower():
        score += 1.5
    if "Missing" in v["name"]:
        score -= 1
    return round(score, 1)

def prioritize(vulns):
    for v in vulns:
        v["ai_score"] = ai_risk_score(v)
    return sorted(vulns, key=lambda x: x["ai_score"], reverse=True)

# ================== HEATMAP ==================
def heatmap(vulns):
    m = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for v in vulns:
        m[v["severity"]] += 1
    return [f"{k:<8} {'█'*v} {v}" for k,v in m.items()]

# ================== NVD LOOKUP ==================
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def nvd_lookup(keyword):
    findings = []
    try:
        r = requests.get(NVD_API, params={"keywordSearch":keyword,"resultsPerPage":2}, timeout=15)
        data = r.json()
        for i in data.get("vulnerabilities",[]):
            cve = i["cve"]
            cvss = 0.0
            if "cvssMetricV31" in cve.get("metrics",{}):
                cvss = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            findings.append({
                "name": keyword,
                "cve": cve["id"],
                "cvss": cvss,
                "severity": cvss_severity(cvss),
                "impact": cve["descriptions"][0]["value"][:120],
                "recommendation": "Upgrade / patch affected component"
            })
    except:
        pass
    return findings

# ================== ASYNC HTTP ==================
async def fetch(session,url):
    try:
        async with session.get(url,timeout=TIMEOUT,ssl=False) as r:
            return await r.text(), r.headers
    except:
        return "",{}

# ================== RECON ==================
async def subdomains(domain):
    url=f"https://crt.sh/?q=%25.{domain}&output=json"
    subs=set()
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(url) as r:
                for e in await r.json():
                    subs.add(e["name_value"])
        except: pass
    return list(subs)

def live(h):
    try:
        socket.gethostbyname(h); return True
    except: return False

# ================== WEB ==================
SEC_HEADERS=["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options"]

async def header_check(url):
    async with aiohttp.ClientSession() as s:
        _,h=await fetch(s,url)
        return [x for x in SEC_HEADERS if x not in h],h

async def js_files(url):
    async with aiohttp.ClientSession() as s:
        html,_=await fetch(s,url)
        return [urljoin(url,j) for j in re.findall(r'src=["\'](.*?\.js)',html)]

# ================== SECRETS ==================
SECRETS={
 "AWS Key":r"AKIA[0-9A-Z]{16}",
 "Google API":r"AIza[0-9A-Za-z_-]{35}",
 "JWT":r"eyJ[A-Za-z0-9_-]+\."
}

async def secret_scan(js):
    leaks=[]
    async with aiohttp.ClientSession() as s:
        for j in js:
            body,_=await fetch(s,j)
            for k,r in SECRETS.items():
                if re.search(r,body):
                    leaks.append(f"{k} in {j}")
    return leaks

# ================== NMAP ==================
def nmap_scan(t):
    try:
        return subprocess.check_output(["nmap","-sV","-T4",t],stderr=subprocess.DEVNULL).decode()
    except:
        return ""

# ================== REPORT ==================
def report(target,results,vulns):
    os.makedirs(f"{OUTPUT_DIR}/{target}",exist_ok=True)
    path=f"{OUTPUT_DIR}/{target}/report.md"
    with open(path,"w") as f:
        f.write(f"# AEGIS-ONE ULTIMATE REPORT\n\nTarget: **{target}**\nDate: {datetime.now()}\n\n")
        for k,v in results.items():
            f.write(f"## {k}\n")
            for i in v: f.write(f"- {i}\n")
            f.write("\n")

        f.write("## Risk Heatmap\n")
        for h in heatmap(vulns): f.write(f"- {h}\n")

        f.write("\n## AI-Prioritized Vulnerabilities\n")
        for v in prioritize(vulns):
            f.write(f"""
### {v['name']}
- CVE: {v['cve']}
- CVSS: {v['cvss']}
- Severity: {v['severity']}
- AI Risk Score: {v['ai_score']}
- Impact: {v['impact']}
- Recommendation: {v['recommendation']}
""")
    print(f"[+] Report saved → {path}")

# ================== MAIN ==================
async def main():
    p=argparse.ArgumentParser()
    p.add_argument("-t","--target",required=True)
    p.add_argument("--nmap",action="store_true")
    a=p.parse_args()

    t=a.target; url="https://"+t
    results={}; vulns=[]

    subs=await subdomains(t)
    results["Live Subdomains"]=[s for s in subs if live(s)]

    missing,headers=await header_check(url)
    results["Missing Headers"]=missing

    if missing:
        vulns.append({
            "name":"Missing Security Headers",
            "cve":"CWE-693",
            "cvss":6.1,
            "severity":"Medium",
            "impact":"Increased XSS / clickjacking risk",
            "recommendation":"Implement recommended security headers"
        })

    js=await js_files(url)
    results["JavaScript Files"]=js
    leaks=await secret_scan(js)
    results["Secrets Found"]=leaks

    for l in leaks:
        vulns.append({
            "name":"Exposed Secret",
            "cve":"N/A",
            "cvss":9.5,
            "severity":"Critical",
            "impact":"Credential compromise",
            "recommendation":"Rotate keys immediately"
        })

    nmap_out=nmap_scan(t) if a.nmap else ""
    if nmap_out:
        results["Nmap"]="Enabled"
        if "Apache" in nmap_out:
            vulns.extend(nvd_lookup("Apache HTTP Server"))

    report(t,results,vulns)

if __name__=="__main__":
    asyncio.run(main())
