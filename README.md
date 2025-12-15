# 🛡️ AegisPTF – Single-File Pentest Framework

AegisPTF is a **single-script penetration testing framework** written in Python for **educational and authorized security testing**.  
It performs **basic reconnaissance, web security checks, payload testing, and secrets detection** with clean, colored CLI output.

---

## ⚠️ DISCLAIMER (IMPORTANT)

> This tool is created **strictly for educational purposes and authorized penetration testing only**.  
> **Do NOT scan any system without explicit written permission.**  
> The author is **not responsible** for misuse or illegal activities.

---

## ✨ FEATURES

- 🔍 Basic reconnaissance (server, ports)
- 🌐 Web security header checks
- 🧪 XSS & SQL Injection payload testing (non-exploitative)
- 🔐 Secrets & token pattern detection
- 🎨 Colored output for easy identification
- 🧩 Single-file (easy to understand & modify)
- 🐧 Designed for Kali Linux

---

## 🧰 REQUIREMENTS

### Operating System
- Kali Linux / Linux (recommended)

### Tools & Libraries
- Python 3.8+
- `requests`
- `nmap` (optional)

---

## 📦 INSTALLATION (STEP-BY-STEP)

### 🔹 Step 1: Clone the Repository
```bash
git clone https://github.com/Fasal17/AegisPTF.git
````

### 🔹 Step 2: Navigate into the Project

```bash
cd AegisPTF
```

### 🔹 Step 3: Install Python Dependencies

```bash
pip3 install requests
```

### 🔹 Step 4: Install Nmap (Optional)

```bash
sudo apt update
sudo apt install nmap -y
```

---

## 🚀 USAGE (STEP-BY-STEP)

### 🔹 Basic Scan

```bash
python3 aegis_ptf.py -t https://example.com
```

### 🔹 Scan with Nmap Service Detection

```bash
python3 aegis_ptf.py -t https://example.com --nmap
---

## 🧠 WHAT THIS TOOL CAN & CANNOT DO

### ✅ CAN DO

* Identify missing security headers
* Detect reflected input (basic)
* Detect SQL error messages
* Find exposed tokens/keys (pattern-based)
* Perform light recon safely


## 🗂️ PROJECT STRUCTURE

```text
AegisPTF/
├── aegis_ptf.py      # Main single-file tool
├── README.md         # Documentation
└── .gitignore
```


## 🛡️ LEGAL & ETHICAL USE

Use this tool **ONLY** on:

* Your own systems
* Lab environments
* Targets with **written permission**

Recommended practice labs:

* OWASP Juice Shop
* DVWA
* PortSwigger Web Security Academy

---
