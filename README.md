# Js_vulenrable_scanner_extensions
# 🔍 SecureJS - JavaScript Vulnerability Scanner (Chrome Extension)

A Chrome extension that scans subdomains of a target domain, extracts JavaScript libraries, detects versions, and checks for known vulnerabilities via [OSV.dev](https://osv.dev).

---

## ✨ Features
- Fetches subdomains using **crt.sh**
- Detects JS libraries (jQuery, React, Angular, Vue, Lodash, etc.)
- Extracts versions from filenames and file content
- Checks vulnerabilities via **OSV.dev API**
- Real-time scan summary (Total JS vs Vulnerable JS)
- User-friendly popup interface
- Chrome Extension (Manifest V3) – no CLI required

---

## 📂 Project Structure
js-vuln-scanner/
├── manifest.json
├── popup.html
├── popup.js
├── background.js
├── icons/
├── README.md
└── screenshots/


## 🚀 How to Run Locally
1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/js-vuln-scanner.git
   cd js-vuln-scanner
Open Chrome and go to:

arduino
Copy code
chrome://extensions/
Enable Developer Mode (top-right).

Click Load unpacked and select your project folder.

Pin the extension → click the icon → run a scan 🚀.

🖼️ Screenshots
![Popup](screenshots/js_vulnerabilit1.PNG)
![Results](screenshots/js_vulnerability.PNG)

📖 Usage Example
Open any website (e.g., example.com)

Click the extension → it will:

Extract subdomains via crt.sh

Collect JS files

Detect library + version

Query vulnerabilities from OSV.dev

Shows real-time results inside popup.

⚠️ Disclaimer
This tool is for educational and research purposes only.
Do not scan domains without proper authorization.
