import requests
import argparse
import json
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

init(autoreset=True)

visited_links = set()
lock = threading.Lock()

results = {
    "target": "",
    "pages_scanned": 0,
    "forms_found": 0,
    "xss": [],
    "sqli": []
}

# ---------------------- CRAWLER ---------------------- #
def get_links(url, target_url):
    links = []
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            link = urljoin(url, a_tag["href"])
            if urlparse(link).netloc == urlparse(target_url).netloc:
                links.append(link)
    except:
        pass
    return links


# ---------------------- XSS TEST ---------------------- #
def test_xss(form, base_url):
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")

    data = {}
    for input_tag in inputs:
        name = input_tag.get("name")
        if name:
            data[name] = "<script>alert('XSS')</script>"

    full_url = urljoin(base_url, action)

    try:
        if method == "post":
            res = requests.post(full_url, data=data)
        else:
            res = requests.get(full_url, params=data)

        if "<script>alert('XSS')</script>" in res.text:
            print(Fore.RED + f"[!] XSS Detected → {full_url}")
            results["xss"].append(full_url)
    except:
        pass


# ---------------------- SQLi TEST ---------------------- #
def test_sqli(form, base_url):
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")

    data = {}
    for input_tag in inputs:
        name = input_tag.get("name")
        if name:
            data[name] = "' OR 1=1--"

    full_url = urljoin(base_url, action)

    try:
        if method == "post":
            res = requests.post(full_url, data=data)
        else:
            res = requests.get(full_url, params=data)

        errors = ["sql", "syntax", "mysql", "error", "warning"]
        for error in errors:
            if error in res.text.lower():
                print(Fore.RED + f"[!] SQL Injection Detected → {full_url}")
                results["sqli"].append(full_url)
                break
    except:
        pass


# ---------------------- PAGE SCAN ---------------------- #
def scan_page(url, target_url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        with lock:
            results["pages_scanned"] += 1
            results["forms_found"] += len(forms)

        print(Fore.YELLOW + f"\n[~] Scanning: {url}")
        print(Fore.GREEN + f"[+] Forms Found: {len(forms)}")

        for form in forms:
            test_xss(form, url)
            test_sqli(form, url)

    except:
        pass


# ---------------------- CRAWLER LOOP ---------------------- #
def crawl(target_url, max_pages):
    to_scan = [target_url]

    while to_scan and len(visited_links) < max_pages:
        url = to_scan.pop(0)

        if url not in visited_links:
            visited_links.add(url)
            scan_page(url, target_url)

            links = get_links(url, target_url)
            for link in links:
                if link not in visited_links:
                    to_scan.append(link)


# ---------------------- MAIN FUNCTION ---------------------- #
def main():
    parser = argparse.ArgumentParser(description="Ultimate Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--depth", type=int, default=10, help="Number of pages to crawl")
    parser.add_argument("--output", default="report.json", help="Output report file")
    args = parser.parse_args()

    target_url = args.url
    max_pages = args.depth
    output_file = args.output

    results["target"] = target_url

    print(Fore.CYAN + "\n[+] Starting Advanced Security Scan on:", target_url)

    crawl(target_url, max_pages)

    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    with open("report.txt", "w") as f:
        f.write(json.dumps(results, indent=4))

    print(Fore.CYAN + "\n========== FINAL SUMMARY ==========")
    print(Fore.GREEN + f"Pages Scanned: {results['pages_scanned']}")
    print(Fore.GREEN + f"Forms Found: {results['forms_found']}")
    print(Fore.RED + f"XSS Found: {len(results['xss'])}")
    print(Fore.RED + f"SQLi Found: {len(results['sqli'])}")
    print(Fore.CYAN + f"Report saved to: {output_file}")
    print(Fore.CYAN + "Scan Completed Successfully 🚀")


# ---------------------- ENTRY POINT ---------------------- #
if __name__ == "__main__":
    main()