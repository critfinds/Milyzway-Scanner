milyzway — Modular Async Vulnerability Scanner (starter)

A modular, production-ready starter for a Python-based vulnerability scanner focused on CORS, OAuth/OIDC heuristics, and SSRF candidate discovery.
This repository is designed as a flexible framework you can extend with more plugins, fuzzers, or interaction-service integrations (Interactsh / Burp Collaborator) once you have authorization to test targets.

⚠️ IMPORTANT — This project is for authorized security testing only. Do not scan systems you do not own or do not have explicit written permission to test. See “Safety & Responsible Testing” below.

Features

Async, rate-limited scanning using aiohttp + aiolimiter for high throughput with care.

Plugin architecture — add new checks as independent plugins.

Starter plugins:

cors — non-destructive checks for CORS misconfigurations.

oauth — heuristics for OAuth/OIDC discovery, potential implicit-flow usage, and redirect parameters.

ssrf — safe candidate enumeration for possible SSRF injection points (no automatic payload firing).

Config-driven (YAML) with concurrency and rate-limit settings.

Dockerfile and example targets.txt for easy deployment.

Output written to scan_results.json (JSON array of findings).

Quick start
Build & run with Docker
# build
docker build -t vulnscanner:local .

# run (mount a local examples folder if you want to supply targets)
docker run --rm -v $(pwd)/examples:/opt/vulnscanner/examples vulnscanner:local


By default the container runs:

python -m scanner.app --targets examples/targets.txt

Run locally (no Docker)
python -m pip install -r requirements.txt
python -m scanner.app --targets examples/targets.txt

Command-line flags
python -m scanner.app --config config.yml --targets examples/targets.txt


--config — path to YAML config (defaults to config.yml)

--targets — path to a newline-separated file with target URLs (overrides config targets)

Project layout
vulnscanner/
├── Dockerfile
├── requirements.txt
├── README.md
├── scanner/
│   ├── app.py                 # entrypoint / orchestrator
│   ├── config.py
│   ├── logger.py
│   ├── plugins/
│   │   ├── base.py
│   │   ├── cors.py
│   │   ├── oauth.py
│   │   ├── probe.py
│   │   └── ssrf.py
│   └── utils/
│       ├── http.py
│       └── reporter.py
└── examples/
    └── targets.txt

Configuration (config.yml)

Example configuration:

targets:
  - "https://example.com"
enabled_plugins:
  - cors
  - oauth
  - ssrf
concurrency: 50
rate_limit: 10


Key fields:

targets — list of target base URLs (or supply --targets file)

enabled_plugins — list of plugin module names to load from scanner.plugins

concurrency — number of concurrent target workers

rate_limit — requests per second per requester instance

Output

Results are written to scan_results.json by default. The format is a JSON array; each item looks like:

{
  "plugin": "cors",
  "target": "https://example.com",
  "result": {
    "cors_findings": [
      {
        "type": "Reflected origin allowed",
        "origin_tested": "https://evil.example",
        "header_acao": "https://evil.example",
        "header_acredentials": null,
        "note": "Server allows this Origin; verify it shouldn't be dynamic/reflected."
      }
    ]
  }
}

Plugin development guide

Plugins live in scanner/plugins and should:

Subclass scanner.plugins.base.BasePlugin

Set name = "<pluginname>"

Implement async run(self, target, requester) which returns:

None when no finding

a dict describing findings when something relevant is found

Example pattern:

from .base import BasePlugin

class MyPlugin(BasePlugin):
    name = "myplugin"
    async def run(self, target, requester):
        resp = await requester.request("GET", target)
        if not resp:
            return None
        text = await resp.text()
        if "something-bad" in text:
            return {"my_findings": ["evidence here"]}
        return None


requester is an instance of AioRequester (see scanner/utils/http.py) — use it for rate-limited requests. It returns aiohttp response objects.

SSRF & Interaction Services (Important guidance)

The included SSRF plugin only enumerates candidate parameters and does not attempt exploit payloads.

Integrating an interaction service (e.g., Interactsh, Burp Collaborator) enables automated SSRF detection by hosting callback URIs. Only perform active SSRF payloads against targets you have explicit authorization to test.

If you add interaction service calls, implement thorough logging and a --dry-run safety mode. Also add limits to the number of external callbacks per target.

Safety & responsible testing

You must have written permission before scanning or testing any target you do not own.

Avoid destructive checks. The supplied plugins are conservative and nondestructive.

Respect rate limits and do not overload production systems.

Keep records of authorization and test scopes. If you find critical vulnerabilities, follow a responsible disclosure process with the owner.

Use --dry-run for enumeration-only behaviour (you can add this flag in app.py).

Testing & development tips

Write unit tests that mock AioRequester sessions to avoid hitting the network during CI.

Maintain a set of local HTML fixtures for deterministic plugin tests.

Add a --limit or --one-target option during development to iterate quickly.

Consider adding recorded HTTP fixtures (VCR-style) for plugin unit tests.

Roadmap / Next steps you might want to implement

Authenticated scanning flows (session cookies, OAuth client credentials, JWT handling).

Interaction service integration (Interactsh client).

Fuzzing engine + template-based payloads (safe defaults).

Output to SQLite/Postgres, or an HTML dashboard.

CLI plugin toggles, verbose logging, and structured severity/risk scoring for findings.

Plugin sandboxing & worker isolation.

Contribution

Contributions, issues, and feature requests are welcome. If you add new checks that perform active exploitation, mark them clearly and add config switches to enable them; never run active/exploit modules by default.

License

This project is provided as-is for educational and authorized security testing purposes. Replace this section with a proper license (e.g., MIT) before sharing publicly.