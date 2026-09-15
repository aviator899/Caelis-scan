# core/crawler.py
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

def crawl(start_url, max_pages=25, timeout=5):
    """Breadth-first crawl restricted to the same domain as start_url."""
    visited = set()
    to_visit = [start_url]
    domain = urlparse(start_url).netloc

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, timeout=timeout)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(resp.text, "html.parser")

            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"])
                next_url = next_url.split("#")[0]  # strip fragments
                if urlparse(next_url).netloc == domain and next_url not in visited:
                    to_visit.append(next_url)
        except requests.RequestException:
            continue

    return list(visited)
