import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def get_internal_links(url, base_url):
    links = []
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if urlparse(link).netloc == urlparse(base_url).netloc:
                links.append(link)
    except:
        pass

    return links