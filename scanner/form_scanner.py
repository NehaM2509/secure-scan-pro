import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_forms(url):
    results = {
        "xss": [],
        "sqli": []
    }

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")

            data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    data[name] = "<script>alert('XSS')</script>"

            full_url = urljoin(url, action)

            if method == "post":
                res = requests.post(full_url, data=data)
            else:
                res = requests.get(full_url, params=data)

            if "<script>alert('XSS')</script>" in res.text:
                results["xss"].append(full_url)

            # SQLi test
            data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    data[name] = "' OR 1=1--"

            if method == "post":
                res = requests.post(full_url, data=data)
            else:
                res = requests.get(full_url, params=data)

            if "sql" in res.text.lower():
                results["sqli"].append(full_url)

    except:
        pass

    return results