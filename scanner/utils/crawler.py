"""
Crawler utility
"""
import asyncio
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class Crawler:
    """
    A simple async web crawler using Playwright
    """
    def __init__(self, requester):
        self.requester = requester
        self.visited = set()
        self.urls = set()
        self.browser = None

    async def _extract_links(self, page, base_url):
        content = await page.content()
        soup = BeautifulSoup(content, "html.parser")
        links = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            abs_url = urljoin(base_url, href)
            if urlparse(abs_url).netloc == urlparse(base_url).netloc:
                links.add(abs_url)
        return links

    async def crawl(self, page, url, base_url):
        if url in self.visited or not url.startswith(base_url):
            return

        self.visited.add(url)
        self.urls.add(url)

        try:
            await page.goto(url, wait_until="domcontentloaded")
            links = await self._extract_links(page, base_url)
            for link in links:
                await self.crawl(page, link, base_url)
        except Exception:
            pass

    async def start(self, base_url):
        """
        Start the crawling process
        """
        async with async_playwright() as p:
            self.browser = await p.chromium.launch()
            page = await self.browser.new_page()
            await self.crawl(page, base_url, base_url)
            await self.browser.close()
        return list(self.urls)
