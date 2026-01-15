"""
Cross-Site Scripting (XSS) Plugin
"""
import uuid
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin
from scanner.utils.crawler import Crawler

# A small list of common XSS payloads
REFLECTED_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
]

class Plugin(BasePlugin):
    """
    Cross-Site Scripting (XSS) plugin
    """
    def __init__(self):
        self.name = "xss"
        self.description = "Detects Cross-Site Scripting (XSS) vulnerabilities"

    async def _test_reflected_xss(self, target: str, requester, oast_server: str = None):
        vulnerabilities = []
        # Test for XSS in URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        for param, values in query_params.items():
            for payload in REFLECTED_PAYLOADS:
                new_query_params = query_params.copy()
                new_query_params[param] = payload
                new_url = parsed_url._replace(query=urlencode(new_query_params, doseq=True)).geturl()
                
                try:
                    response = await requester.get(new_url)
                    if not response or not isinstance(response, dict):
                        continue
                    content = response.get("text") or ""
                    if payload in content:
                        vulnerabilities.append({
                            "type": "reflected_xss",
                            "param": param,
                            "payload": payload,
                            "message": f"Reflected XSS found in URL parameter '{param}'.",
                            "severity": "medium",
                            "confidence": "firm",
                        })
                except Exception:
                    pass

        # Test for XSS in forms
        try:
            response = await requester.get(target)
            if not response or not isinstance(response, dict): raise ValueError
            soup = BeautifulSoup(response.get("text") or "", "html.parser")
            forms = soup.find_all("form")
        except Exception:
            forms = []

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all(["input", "textarea", "select"])
            form_url = urljoin(target, action)

            for payload in REFLECTED_PAYLOADS:
                data = {i.get("name"): payload for i in inputs if i.get("name")}
                if not data: continue
                
                try:
                    if method == "post":
                        response = await requester.post(form_url, data=data)
                    else:
                        response = await requester.get(form_url, params=data)
                    
                    if not response or not isinstance(response, dict):
                        continue
                    content = response.get("text") or ""
                    if payload in content:
                        vulnerabilities.append({
                            "type": "reflected_xss_form",
                            "url": form_url,
                            "payload": payload,
                            "message": f"Reflected XSS found in form on page {target}.",
                            "severity": "medium",
                            "confidence": "firm",
                        })
                except Exception:
                    pass
        return vulnerabilities

    async def _test_stored_xss(self, target: str, requester, oast_server: str = None):
        vulnerabilities = []
        unique_payloads = {}

        # 1. Crawl the application to find forms
        crawler = Crawler(requester)
        crawled_urls = await crawler.start(target)

        # 2. Submit forms with unique payloads
        for url in crawled_urls:
            try:
                response = await requester.get(url)
                if not response or not isinstance(response, dict): continue
                content = response.get("text") or ""
                soup = BeautifulSoup(content, "html.parser")
                forms = soup.find_all("form")
            except Exception:
                forms = []

            for form in forms:
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = form.find_all(["input", "textarea", "select"])
                form_url = urljoin(url, action)
                
                payload = f"<script>alert('{uuid.uuid4()}')</script>"
                unique_payloads[payload] = form_url

                data = {i.get("name"): payload for i in inputs if i.get("name")}
                if not data: continue
                
                try:
                    if method == "post":
                        await requester.post(form_url, data=data)
                    else:
                        await requester.get(form_url, params=data)
                except Exception:
                    pass

        # 3. Re-crawl the application to check for stored payloads
        for url in crawled_urls:
            try:
                response = await requester.get(url)
                if not response or not isinstance(response, dict): continue
                content = response.get("text") or ""
                for payload, form_url in unique_payloads.items():
                    if payload in content:
                        vulnerabilities.append({
                            "type": "stored_xss",
                            "url": url,
                            "payload": payload,
                            "origin_form": form_url,
                            "message": f"Stored XSS found at {url} from form at {form_url}.",
                            "severity": "high",
                            "confidence": "firm",
                        })
            except Exception:
                pass

        return vulnerabilities

    async def run(self, target: str, requester, oast_server: str = None):
        reflected_vulnerabilities = await self._test_reflected_xss(target, requester, oast_server)

        # Stored XSS requires the Crawler which uses Playwright.
        # If Playwright browsers aren't installed, we gracefully skip stored XSS testing.
        try:
            stored_vulnerabilities = await self._test_stored_xss(target, requester, oast_server)
        except Exception:
            stored_vulnerabilities = []

        return reflected_vulnerabilities + stored_vulnerabilities
