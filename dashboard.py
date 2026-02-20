import streamlit as st
import requests
import json
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

st.set_page_config(
    page_title="Advanced Web Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------- STYLING ---------------------- #
st.markdown("""
<style>
body {
    background-color: #0e1117;
}
h1 {
    background: linear-gradient(90deg, #00f5a0, #00d9f5);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.stMetric {
    background-color: #1c1f26;
    padding: 15px;
    border-radius: 10px;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Advanced Web Vulnerability Scanner")

st.markdown("Scan websites for common vulnerabilities like XSS and SQL Injection.")

# ---------------------- INPUT ---------------------- #
target_url = st.text_input("🌐 Enter Target URL (include http:// or https://)")
depth = st.slider("🔎 Crawl Depth", 1, 20, 5)

start_scan = st.button("🚀 Start Scan")

# ---------------------- SCAN FUNCTION ---------------------- #
def scan_target(target_url, max_pages):

    visited = set()
    results = {
        "target": target_url,
        "pages_scanned": 0,
        "forms_found": 0,
        "xss": [],
        "sqli": []
    }

    def get_links(url):
        links = []
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                if urlparse(link).netloc == urlparse(target_url).netloc:
                    links.append(link)
        except:
            pass
        return links

    def scan_page(url):
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            results["pages_scanned"] += 1
            results["forms_found"] += len(forms)

            for form in forms:
                test_xss(form, url)
                test_sqli(form, url)
        except:
            pass

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
                results["xss"].append(full_url)
        except:
            pass

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
                    results["sqli"].append(full_url)
                    break
        except:
            pass

    to_scan = [target_url]

    while to_scan and len(visited) < max_pages:
        url = to_scan.pop(0)
        if url not in visited:
            visited.add(url)
            scan_page(url)
            links = get_links(url)
            for link in links:
                if link not in visited:
                    to_scan.append(link)

    return results


# ---------------------- EXECUTION ---------------------- #
if start_scan and target_url:

    with st.spinner("Scanning... Please wait..."):
        results = scan_target(target_url, depth)
        time.sleep(1)

    st.success("Scan Completed!")

    total_vulns = len(results["xss"]) + len(results["sqli"])

    # ---------------------- RISK SCORE ---------------------- #
    if total_vulns == 0:
        risk = "Low"
        risk_color = "🟢"
    elif total_vulns <= 3:
        risk = "Medium"
        risk_color = "🟡"
    elif total_vulns <= 6:
        risk = "High"
        risk_color = "🟠"
    else:
        risk = "Critical"
        risk_color = "🔴"

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Pages Scanned", results["pages_scanned"])
    col2.metric("Forms Found", results["forms_found"])
    col3.metric("Total Vulnerabilities", total_vulns)
    col4.metric("Risk Level", f"{risk_color} {risk}")

    st.markdown("---")

    # ---------------------- PIE CHART ---------------------- #
    chart_data = pd.DataFrame({
        "Type": ["XSS", "SQL Injection"],
        "Count": [len(results["xss"]), len(results["sqli"])]
    })

    st.subheader("Vulnerability Distribution")
    st.bar_chart(chart_data.set_index("Type"))

    st.markdown("---")

    # ---------------------- DETAILS ---------------------- #
    st.subheader("Detailed Findings")

    if results["xss"]:
        st.markdown("### 🔥 XSS Vulnerabilities")
        for vuln in results["xss"]:
            with st.expander(vuln):
                st.write("Severity: 🔴 High")
    else:
        st.success("No XSS vulnerabilities found.")

    if results["sqli"]:
        st.markdown("### 💉 SQL Injection Vulnerabilities")
        for vuln in results["sqli"]:
            with st.expander(vuln):
                st.write("Severity: 🔴 High")
    else:
        st.success("No SQL Injection vulnerabilities found.")

    # ---------------------- DOWNLOAD REPORT ---------------------- #
    st.download_button(
        label="📥 Download JSON Report",
        data=json.dumps(results, indent=4),
        file_name="security_report.json",
        mime="application/json"
    )

    st.markdown("---")
    st.caption("🚀 Built by Neha | Cybersecurity Project")