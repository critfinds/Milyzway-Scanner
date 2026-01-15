"""
Professional Bug Bounty Report Generator
Generates comprehensive, professional reports for bug bounty submissions
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path


class BugBountyReportGenerator:
    """Generates professional bug bounty reports"""

    def __init__(self):
        self.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_report(self, vulnerabilities: List[Dict[str, Any]], target: str, output_format: str = "markdown") -> str:
        """Generate a comprehensive bug bounty report"""

        if output_format == "markdown":
            return self._generate_markdown_report(vulnerabilities, target)
        elif output_format == "json":
            return self._generate_json_report(vulnerabilities, target)
        elif output_format == "html":
            return self._generate_html_report(vulnerabilities, target)
        else:
            return self._generate_markdown_report(vulnerabilities, target)

    def _generate_markdown_report(self, vulnerabilities: List[Dict[str, Any]], target: str) -> str:
        """Generate Markdown format report (most common for bug bounties)"""

        # Group vulnerabilities by severity
        critical = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high = [v for v in vulnerabilities if v.get("severity") == "high"]
        medium = [v for v in vulnerabilities if v.get("severity") == "medium"]
        low = [v for v in vulnerabilities if v.get("severity") == "low"]

        report = f"""# Security Vulnerability Report

**Target:** {target}
**Report Date:** {self.report_date}
**Scanner:** Milyzway Advanced Vulnerability Scanner
**Total Vulnerabilities Found:** {len(vulnerabilities)}

## Executive Summary

This report documents security vulnerabilities discovered during automated security testing of {target}.

**Severity Breakdown:**
- Critical: {len(critical)}
- High: {len(high)}
- Medium: {len(medium)}
- Low: {len(low)}

---

"""

        # Critical vulnerabilities first
        if critical:
            report += "## Critical Severity Vulnerabilities\n\n"
            for i, vuln in enumerate(critical, 1):
                report += self._format_vulnerability_markdown(vuln, i)

        if high:
            report += "## High Severity Vulnerabilities\n\n"
            for i, vuln in enumerate(high, 1):
                report += self._format_vulnerability_markdown(vuln, i)

        if medium:
            report += "## Medium Severity Vulnerabilities\n\n"
            for i, vuln in enumerate(medium, 1):
                report += self._format_vulnerability_markdown(vuln, i)

        if low:
            report += "## Low Severity Vulnerabilities\n\n"
            for i, vuln in enumerate(low, 1):
                report += self._format_vulnerability_markdown(vuln, i)

        # Add recommendations
        report += self._generate_recommendations(vulnerabilities)

        return report

    def _format_vulnerability_markdown(self, vuln: Dict[str, Any], index: int) -> str:
        """Format a single vulnerability in markdown"""

        vuln_type = vuln.get("type", "Unknown")
        message = vuln.get("message", "No description")
        severity = vuln.get("severity", "unknown").upper()
        confidence = vuln.get("confidence", "unknown").title()
        impact = vuln.get("impact", "Not specified")
        location = vuln.get("location", vuln.get("context", "Unknown location"))
        bounty_potential = vuln.get("bounty_potential", "Not estimated")

        report = f"""### {index}. {vuln_type.replace("_", " ").title()}

**Severity:** {severity}
**Confidence:** {confidence}
**Bounty Potential:** {bounty_potential}

#### Description
{message}

#### Location
```
{location}
```

#### Impact
{impact}

"""

        # Add specific details
        if "payload" in vuln:
            report += f"""#### Proof of Concept

**Payload:**
```
{vuln['payload']}
```

"""

        if "exploitation" in vuln:
            report += f"""#### Exploitation Steps
{vuln['exploitation']}

"""

        # Add technical details
        technical_details = []
        if "database" in vuln:
            technical_details.append(f"- Database: {vuln['database']}")
        if "waf_detected" in vuln and vuln["waf_detected"]:
            technical_details.append(f"- WAF Detected: Yes")
        if "chain" in vuln:
            technical_details.append(f"- Chain: {vuln['chain']}")
        if "original_id" in vuln:
            technical_details.append(f"- Original ID: {vuln['original_id']}")
        if "accessible_ids" in vuln:
            technical_details.append(f"- Accessible IDs: {', '.join(map(str, vuln['accessible_ids']))}")

        if technical_details:
            report += "#### Technical Details\n"
            report += "\n".join(technical_details) + "\n\n"

        # Add recommendation
        if "recommendation" in vuln:
            report += f"""#### Remediation
{vuln['recommendation']}

"""

        # Add references
        if "reference" in vuln:
            report += f"""#### References
{vuln['reference']}

"""

        if "cvss" in vuln:
            report += f"""#### CVSS Score
{vuln['cvss']}

"""

        report += "---\n\n"

        return report

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate overall recommendations section"""

        report = """## Overall Recommendations

Based on the vulnerabilities discovered, the following actions are recommended:

### Immediate Actions (Critical/High)
"""

        critical_high = [v for v in vulnerabilities if v.get("severity") in ["critical", "high"]]

        if critical_high:
            report += "1. Address all Critical and High severity vulnerabilities immediately\n"
            report += "2. Implement a Web Application Firewall (WAF) if not already present\n"
            report += "3. Review and strengthen authentication mechanisms\n"
            report += "4. Implement input validation and output encoding\n"
        else:
            report += "No critical or high severity vulnerabilities found.\n"

        report += """
### Short-term Actions (Medium)
1. Implement rate limiting and anti-automation measures
2. Enable security headers (CSP, HSTS, X-Frame-Options, etc.)
3. Conduct security code review
4. Implement logging and monitoring

### Long-term Actions
1. Establish a Security Development Lifecycle (SDL)
2. Regular security testing and audits
3. Security awareness training for developers
4. Bug bounty program (if not already present)
"""

        report += """
## Disclaimer

This report is generated by an automated security scanner. While efforts have been made to ensure accuracy:
- False positives may occur
- Manual verification is recommended before exploitation
- Some vulnerabilities may require additional context to exploit
- The absence of findings does not guarantee security

For critical applications, a manual penetration test by certified security professionals is recommended.

---

**Report Generated by:** Milyzway Advanced Vulnerability Scanner
**Contact:** For questions about this report, please contact your security team.
"""

        return report

    def _generate_json_report(self, vulnerabilities: List[Dict[str, Any]], target: str) -> str:
        """Generate JSON format report"""

        report_data = {
            "report_info": {
                "target": target,
                "date": self.report_date,
                "scanner": "Milyzway Advanced Vulnerability Scanner",
                "version": "2.0",
            },
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": {
                    "critical": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
                    "high": len([v for v in vulnerabilities if v.get("severity") == "high"]),
                    "medium": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
                    "low": len([v for v in vulnerabilities if v.get("severity") == "low"]),
                }
            },
            "vulnerabilities": vulnerabilities
        }

        return json.dumps(report_data, indent=2)

    def _generate_html_report(self, vulnerabilities: List[Dict[str, Any]], target: str) -> str:
        """Generate HTML format report"""

        critical = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high = [v for v in vulnerabilities if v.get("severity") == "high"]
        medium = [v for v in vulnerabilities if v.get("severity") == "medium"]
        low = [v for v in vulnerabilities if v.get("severity") == "low"]

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .vulnerability {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            border-left: 5px solid #ccc;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }}
        .severity-critical {{ background-color: #dc3545; }}
        .severity-high {{ background-color: #fd7e14; }}
        .severity-medium {{ background-color: #ffc107; }}
        .severity-low {{ background-color: #28a745; }}
        code {{
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        h1, h2, h3 {{ color: #333; }}
        .stat {{
            display: inline-block;
            margin: 10px 20px 10px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Vulnerability Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Report Date:</strong> {self.report_date}</p>
        <p><strong>Scanner:</strong> Milyzway Advanced Vulnerability Scanner</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total Vulnerabilities Found: <strong>{len(vulnerabilities)}</strong></p>
        <div class="stat">
            <span class="severity-badge severity-critical">CRITICAL: {len(critical)}</span>
        </div>
        <div class="stat">
            <span class="severity-badge severity-high">HIGH: {len(high)}</span>
        </div>
        <div class="stat">
            <span class="severity-badge severity-medium">MEDIUM: {len(medium)}</span>
        </div>
        <div class="stat">
            <span class="severity-badge severity-low">LOW: {len(low)}</span>
        </div>
    </div>
"""

        # Add vulnerabilities
        all_vulns = critical + high + medium + low
        for i, vuln in enumerate(all_vulns, 1):
            severity = vuln.get("severity", "unknown")
            severity_class = severity.lower()

            html += f"""
    <div class="vulnerability {severity_class}">
        <h3>{i}. {vuln.get('type', 'Unknown').replace('_', ' ').title()}</h3>
        <span class="severity-badge severity-{severity_class}">{severity.upper()}</span>
        <span class="severity-badge" style="background-color: #6c757d;">
            {vuln.get('confidence', 'unknown').title()}
        </span>

        <p><strong>Description:</strong> {vuln.get('message', 'No description')}</p>
        <p><strong>Location:</strong> <code>{vuln.get('location', vuln.get('context', 'Unknown'))}</code></p>
        <p><strong>Impact:</strong> {vuln.get('impact', 'Not specified')}</p>
"""

            if "bounty_potential" in vuln:
                html += f"""        <p><strong>Bounty Potential:</strong> {vuln['bounty_potential']}</p>"""

            if "payload" in vuln:
                html += f"""
        <p><strong>Proof of Concept:</strong></p>
        <pre><code>{vuln['payload'][:200]}</code></pre>
"""

            html += "    </div>\n"

        html += """
    <div class="summary">
        <h2>Disclaimer</h2>
        <p>This report is generated by an automated security scanner. Manual verification is recommended before exploitation.
        For critical applications, a manual penetration test by certified security professionals is recommended.</p>
    </div>
</body>
</html>"""

        return html

    def save_report(self, report: str, output_path: str):
        """Save report to file"""
        try:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            return True
        except Exception as e:
            print(f"Error saving report: {e}")
            return False
