"""
Crawler utility
"""
import asyncio
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class Crawler:
    """
    A simple async web crawler
    """
    def __init__(self, base_url, requester):
        self.base_url = base_url
        self.requester = requester
        self.visited = set()
        self.urls = set()

    async def crawl(self, url):
        """
        Crawl a single URL
        """
        if url in self.visited or not url.startswith(self.base_url):
            return

        self.visited.add(url)
        self.urls.add(url)

        try:
            response = await self.requester.get(url)
            soup = BeautifulSoup(await response.text(), "html.parser")

            for link in soup.find_all("a", href=True):
                href = link["href"]
                abs_url = urljoin(url, href)
                if urlparse(abs_url).netloc == urlparse(self.base_url).netloc:
                    await self.crawl(abs_url)
        except Exception:
            pass

    async def start(self):
        """
        Start the crawling process
        """
        await self.crawl(self.base_url)
        return list(self.urls)
