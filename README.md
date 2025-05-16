# ThreatMeld – Burp Suite Security Response Analyzer

**ThreatMeld** is a lightweight Burp Suite extension that passively analyzes proxy traffic responses and flags potential security vulnerabilities. It maps findings to OWASP standards and generates a CSV report with actionable insights.

---

## 🔍 Features
  
- Passive scanning of proxy traffic
- Detection of:
  - Cross-Site Scripting (XSS)
  - Open Redirects
  - SQL Injection (basic pattern matching)
  - Information Disclosure
- Maps issues to OWASP test IDs
- Severity classification (High, Medium, Low)
- Outputs findings in a CSV report (`ThreatMeld_Report.csv`)

---

## 🛠 Installation & Usage

1. **Clone the Repo:**
   ```bash
   git clone https://github.com/yourusername/threatmeld.git
   cd threatmeld

2. Prepare Burp Suite:
   Open Burp Suite.
   Go to Extender > Extensions.
   Click Add and load threatmeld.py using Jython as the extension type.
3. Start Capturing:
   Ensure proxy traffic is flowing through Burp.
   The extension will automatically analyze responses and log issues to the console and findings list.

4. Generate Report (Optional):
   Call the generate_report() function manually from a Python shell if needed
