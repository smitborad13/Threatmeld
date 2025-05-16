# -*- coding: utf-8 -*-

from burp import IBurpExtender, IProxyListener
import json
import csv


class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ThreatMeld")
        callbacks.registerProxyListener(self)
        print("ThreatMeld Proxy Listener Activated")

    def processProxyMessage(self, messageIsRequest, message):
        try:
            request = message.getMessageInfo()
            analyzed_request = self._helpers.analyzeRequest(request)
            url = analyzed_request.getUrl().toString()

            # ✅ Ignore trusted domains to reduce false positives
            trusted_sources = ["youtube.com", "google.com", "cdnjs.cloudflare.com", "microsoft.com", "akamai.com"]
            if any(domain in url for domain in trusted_sources):
                return

            if not messageIsRequest:
                response = request.getResponse()
                if response:
                    response_str = self._helpers.bytesToString(response)

                    # ✅ Detect vulnerabilities in the response
                    detected_issue, evidence = detect_vulnerability(response_str)

                    if detected_issue:
                        print("[+] Found Issue: {} at {}".format(detected_issue, url))

                        test_id, test_name = map_issue_to_owasp(detected_issue)
                        severity = determine_severity(detected_issue)

                        findings.append({
                            "owasp_test": test_name if test_name else "Unknown",
                            "url": url,
                            "description": detected_issue,
                            "severity": severity,
                            "evidence": evidence
                        })
        except Exception as e:
            print("[ERROR] Failed to process proxy message: {}".format(str(e)))

    def generate_report(self):
        report_filename = "ThreatMeld_Report.csv"
        try:
            with open(report_filename, "wb") as csvfile:
                writer = csv.writer(csvfile)

                # Writing the header row
                writer.writerow(["URL", "Security Issue", "Severity", "OWASP Test ID", "Evidence"])

                # Writing data rows
                for finding in findings:
                    writer.writerow([
                        finding["url"],
                        finding["description"],
                        finding["severity"],
                        finding["owasp_test"],
                        finding["evidence"]
                    ])

            print("CSV report generated: {}".format(report_filename))

        except Exception as e:
            print("[ERROR] Failed to write CSV report: {}".format(str(e)))


# Helper Functions
def load_owasp_tests():
    try:
        with open("owasp_wstg.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print("[ERROR] 'owasp_wstg.json' file not found. Ensure the file is in the correct directory.")
        return {}
    except json.JSONDecodeError:
        print("[ERROR] 'owasp_wstg.json' is not a valid JSON file.")
        return {}


def map_issue_to_owasp(issue_description):
    for test_id, test_name in owasp_tests.items():
        if test_name.lower() in issue_description.lower():
            return test_id, test_name
    return None, None


def determine_severity(issue_description):
    """Assign severity based on issue type."""
    high_risk = ["SQL Injection", "Authentication Bypass", "Remote Code Execution"]
    medium_risk = ["Cross-Site Scripting", "Insecure Direct Object Reference"]
    low_risk = ["Information Disclosure"]

    for issue in high_risk:
        if issue.lower() in issue_description.lower():
            return "High"
    for issue in medium_risk:
        if issue.lower() in issue_description.lower():
            return "Medium"
    for issue in low_risk:
        if issue.lower() in issue_description.lower():
            return "Low"

    return "Unknown"


def detect_vulnerability(response_body):
    """Detects security vulnerabilities based on response content"""

    vulnerability_signatures = {
        "SQL Injection": ["syntax error", "You have an error in your SQL syntax", "Unclosed quotation mark"],
        "Cross-Site Scripting (XSS)": ["<script>alert(", "<img src=", "onerror="],
        "Information Disclosure": ["root:x:0:0:", "admin@example.com", "password="],
        "Open Redirect": ["window.location", "document.location"]
    }

    for vuln, signatures in vulnerability_signatures.items():
        for signature in signatures:
            if signature.lower() in response_body.lower():
                # ✅ Ensure the vulnerability is actually executable in an HTML context
                if vuln == "Cross-Site Scripting (XSS)":
                    if "Content-Type: text/html" in response_body:  # Ensure it's within an HTML response
                        return vuln, "Matched keyword: {}".format(signature)
                    else:
                        return None, None  # Ignore non-HTML responses

                return vuln, "Matched keyword: {}".format(signature)

    return None, None  # No vulnerability found


owasp_tests = load_owasp_tests()
findings = []
