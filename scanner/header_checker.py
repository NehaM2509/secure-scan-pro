import requests

def check_headers(url):
    missing = []
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security"
    ]

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header in security_headers:
            if header not in headers:
                missing.append(header)
    except:
        pass

    return missing