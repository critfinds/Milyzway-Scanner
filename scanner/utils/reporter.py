"""Simple result reporter utilities."""
import json
import csv
from pathlib import Path
from typing import Any

def write_json(path: str, data: Any, *, indent: int = 2) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=indent, ensure_ascii=False))
    return p

def write_csv(path: str, data: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "Plugin", "Result"])
        for result in data:
            if result["vulnerabilities"]:
                for vuln in result["vulnerabilities"]:
                    writer.writerow([vuln["target"], vuln["plugin"], str(vuln["result"])])
    return p

def write_html(path: str, data: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        f.write("""<html>
<head>
    <title>Scan Results</title>
    <style>
        body {
            font-family: sans-serif;
        }
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            border: 1px solid #dddddd;
            text-align: left;
            padding: 8px;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <h1>Scan Results</h1>
    <table border=1>
        <tr><th>Target</th><th>Plugin</th><th>Result</th></tr>
""")
        for result in data:
            if result["vulnerabilities"]:
                for vuln in result["vulnerabilities"]:
                    f.write(f"<tr><td>{vuln['target']}</td><td>{vuln['plugin']}</td><td>{str(vuln['result'])}</td></tr>")
        f.write("</table></body></html>")
    return p
 