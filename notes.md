Vuln scanner for my upcoming project


Repo layout

vulnscanner/
├── Dockerfile
├── docker-compose.yml         # optional
├── requirements.txt
├── README.md
├── scanner/
│   ├── __init__.py
│   ├── app.py                 # entrypoint, orchestrator
│   ├── config.py              # YAML/ENV config
│   ├── logger.py
│   ├── plugins/
│   │   ├── __init__.py
│   │   ├── base.py            # plugin base class
│   │   ├── cors.py            # CORS checks (implemented)
│   │   ├── oauth.py           # OAuth misconfig checks (implemented)
│   │   └── ssrf.py            # SSRF checking helpers (safe stub)
│   └── utils/
│       ├── http.py            # aiohttp wrapper, rate limiting, retry
│       └── reporter.py        # output to JSON/CSV/DB
└── examples/
    └── targets.txt            # list of target URLs (one per line)
Dockerfile

FROM python:3.11-slim

# System deps for some libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vulnscanner

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1 \
    TZ=UTC

CMD ["python", "-m", "scanner.app", "--targets", "examples/targets.txt"]
requirements.txt

aiohttp>=3.8
aiolimiter>=1.0
PyYAML>=6.0
uvloop; platform_system != "Windows"
yarl>=1.8
python-dotenv>=1.0
tqdm
scanner/app.py — orchestrator (async, plugin system)

# scanner/app.py
import asyncio
import argparse
import yaml
from pathlib import Path
from scanner.logger import get_logger
from scanner.config import load_config
from scanner.plugins import load_plugins
from scanner.utils.http import AioRequester

LOG = get_logger("vulnscanner")

async def scan_target(target, plugins, requester):
    results = []
    for plugin in plugins:
        try:
            res = await plugin.run(target, requester)
            if res:
                results.append({ "plugin": plugin.name, "target": target, "result": res })
        except Exception as e:
            LOG.exception("Plugin %s failed on %s: %s", plugin.name, target, e)
    return results

async def main_async(args):
    cfg = load_config(args.config)
    requester = AioRequester(rate_limit=cfg.get("rate_limit", 5))
    plugins = load_plugins(cfg.get("enabled_plugins"))
    targets = []
    if args.targets:
        targets = [t.strip() for t in Path(args.targets).read_text().splitlines() if t.strip()]
    else:
        targets = cfg.get("targets", [])

    LOG.info("Starting scan of %d targets with %d plugins", len(targets), len(plugins))

    sem = asyncio.Semaphore(cfg.get("concurrency", 10))
    async def worker(t):
        async with sem:
            return await scan_target(t, plugins, requester)

    tasks = [worker(t) for t in targets]
    all_results = await asyncio.gather(*tasks)
    # flatten and write JSON
    from scanner.utils.reporter import write_json
    write_json("scan_results.json", [r for group in all_results for r in group])
    LOG.info("Scan complete. Results in scan_results.json")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yml")
    parser.add_argument("--targets", help="path to targets file (one per line)")
    args = parser.parse_args()
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()
scanner/plugins/base.py — simple plugin base

# scanner/plugins/base.py
from abc import ABC, abstractmethod

class BasePlugin(ABC):
    name = "base"

    def __init__(self, config=None):
        self.config = config or {}

    @abstractmethod
    async def run(self, target, requester):
        """
        Return None if nothing found, otherwise a dict describing finding(s).
        """
        raise NotImplementedError
scanner/plugins/cors.py — implemented, safe checks

# scanner/plugins/cors.py
from .base import BasePlugin
from yarl import URL

class CORSPlugin(BasePlugin):
    name = "cors"

    async def run(self, target, requester):
        """
        Perform non-destructive CORS misconfiguration checks.
        Strategy:
          - Send an Origin header of a controlled origin and check Access-Control-Allow-Origin
          - Send with credentials and check Access-Control-Allow-Credentials
        """
        findings = []
        test_origins = [
            "https://evil.example",   # generic test origin
            "http://localhost:3000",  # local origin test
        ]
        for origin in test_origins:
            headers = {"Origin": origin}
            # default GET
            resp = await requester.request("GET", target, headers=headers, allow_redirects=True)
            if not resp:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acredentials = resp.headers.get("Access-Control-Allow-Credentials")
            if acao == "*" and acredentials and acredentials.lower() == "true":
                findings.append({
                    "type": "CORS wildcard + credentials",
                    "origin_tested": origin,
                    "header_acao": acao,
                    "header_acredentials": acredentials,
                    "note": "Access-Control-Allow-Origin = '*' with credentials allowed is insecure."
                })
            elif acao and acao == origin:
                findings.append({
                    "type": "Reflected origin allowed",
                    "origin_tested": origin,
                    "header_acao": acao,
                    "header_acredentials": acredentials,
                    "note": "Server allows this Origin; verify it shouldn't be dynamic/reflected."
                })
        if findings:
            return {"cors_findings": findings}
        return None
scanner/plugins/oauth.py — initial checks for common OAuth pitfalls

# scanner/plugins/oauth.py
from .base import BasePlugin
from urllib.parse import urlparse, parse_qs

class OAuthPlugin(BasePlugin):
    name = "oauth"

    async def run(self, target, requester):
        """
        Look for:
         - presence of /.well-known/openid-configuration
         - redirect_uri parameters that might be open redirects (non-exhaustive)
         - implicit flow (response_type=token) usage in auth links found on pages (simple heuristic)
        """
        findings = []

        # 1) discover OpenID config
        well_known = target.rstrip("/") + "/.well-known/openid-configuration"
        resp = await requester.request("GET", well_known, allow_redirects=True)
        if resp and resp.status == 200:
            findings.append({"type": "openid-discovery", "url": well_known})

        # 2) quick scan page for oauth parameters
        resp = await requester.request("GET", target, allow_redirects=True)
        if not resp:
            return None
        text = await resp.text()
        # naive heuristics for auth endpoints
        for keyword in ["response_type=token", "response_type=id_token", "redirect_uri="]:
            if keyword in text:
                findings.append({"type": "oauth-heuristic", "evidence": keyword})

        # 3) check open redirect params (safe detection):
        # look for common params and test them with a harmless redirect target (example.com)
        params_to_check = ["redirect_uri", "next", "return_to", "continue"]
        # gather candidate urls from page (very simple)
        import re
        urls = re.findall(r'href=["\']([^"\']+)["\']', text)
        for u in urls:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query)
            for p in params_to_check:
                if p in qs:
                    # if the param contains a URL we can flag as a possible open redirect parameter
                    findings.append({
                        "type": "open-redirect-param",
                        "url": u,
                        "param": p,
                        "note": "Parameter exists in link; further testing requires legal authorization."
                    })
        if findings:
            return {"oauth_findings": findings}
        return None
scanner/plugins/ssrf.py — safe stub + guidance

# scanner/plugins/ssrf.py
from .base import BasePlugin

class SSRFPlugin(BasePlugin):
    name = "ssrf"

    async def run(self, target, requester):
        """
        SSRF detection is delicate and normally requires an externally-controlled callback (interact service).
        This module will:
          - find parameters that look like URLs in forms/links (heuristic)
          - report candidate injection points only (no automatic payload firing)
        This keeps the starter safe and non-destructive. Implement an interaction service (burp collaborator / interactsh)
        only after you have authorization.
        """
        findings = []
        resp = await requester.request("GET", target, allow_redirects=True)
        if not resp:
            return None
        body = await resp.text()

        import re
        # find likely parameters in links or forms that accept URLs
        # very conservative: look for url=, target=, callback=, endpoint= in query string examples
        matches = re.findall(r'[?&](url|callback|endpoint|target|redirect)=([^&"\'>]+)', body, re.IGNORECASE)
        for param, val in matches:
            findings.append({
                "param": param,
                "value_example": val,
                "note": "Candidate parameter that may accept a URL. Do not send payloads without authorization."
            })
        if findings:
            return {"ssrf_candidates": findings}
        return None
scanner/utils/http.py — aiohttp wrapper with rate limiting + retries

# scanner/utils/http.py
import asyncio
import aiohttp
from aiolimiter import AsyncLimiter
from scanner.logger import get_logger

LOG = get_logger("http")

class AioRequester:
    def __init__(self, rate_limit=5, timeout=20):
        # rate_limit = requests per second
        self._limiter = AsyncLimiter(max_rate=rate_limit, time_period=1)
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session = aiohttp.ClientSession(timeout=self._timeout)

    async def request(self, method, url, **kwargs):
        try:
            async with self._limiter:
                async with self._session.request(method, url, **kwargs) as resp:
                    return resp
        except Exception as e:
            LOG.debug("HTTP request failed: %s %s -> %s", method, url, e)
            return None

    async def close(self):
        await self._session.close()
scanner/utils/reporter.py

# scanner/utils/reporter.py
import json
from pathlib import Path

def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2))
scanner/logger.py

# scanner/logger.py
import logging
def get_logger(name):
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler()
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        h.setFormatter(fmt)
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
    return logger
scanner/plugins/init.py — plugin loader

# scanner/plugins/__init__.py
import importlib
from pathlib import Path
from scanner.logger import get_logger
LOG = get_logger("plugins")

def load_plugins(enabled=None):
    enabled = enabled or ["cors", "oauth", "ssrf"]
    plugins = []
    for name in enabled:
        try:
            mod = importlib.import_module(f"scanner.plugins.{name}")
            # each plugin should expose a class named <CamelCase>Plugin or fallback to first BasePlugin subclass
            cls = None
            for attr in dir(mod):
                o = getattr(mod, attr)
                try:
                    from scanner.plugins.base import BasePlugin
                    if isinstance(o, type) and issubclass(o, BasePlugin) and o is not BasePlugin:
                        cls = o
                        break
                except Exception:
                    pass
            if cls is None:
                LOG.warning("No plugin class found in %s", name)
                continue
            plugins.append(cls())
        except Exception as e:
            LOG.exception("Failed to load plugin %s: %s", name, e)
    return plugins
config.yml — example configuration

targets:
  - "https://example.com"
enabled_plugins:
  - cors
  - oauth
  - ssrf
concurrency: 10
rate_limit: 10
How to run locally
1. build & run locally:

docker build -t vulnscanner:local .
docker run --rm -v$(pwd)/examples:/opt/vulnscanner/examples vulnscanner:local
2. or run locally without Docker:

python -m pip install -r requirements.txt
python -m scanner.app --targets examples/targets.txt
