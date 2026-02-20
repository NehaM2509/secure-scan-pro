import streamlit as st
import json
import os
from scanner.crawler import get_internal_links
from scanner.form_scanner import scan_forms
from scanner.header_checker import check_headers
from scanner.risk_engine import calculate_risk

# ---------------- PAGE CONFIG ---------------- #
st.set_page_config(page_title="SecureScan Pro", layout="wide")

# ---------------- CUSTOM CSS ---------------- #
st.markdown("""
<style>
.main {
    background-color: #0E1117;
}
h1 {
    color: #4CAF50;
}
.metric-card {
    background-color: #1E1E1E;
    padding: 20px;
    border-radius: 12px;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ SecureScan Pro")

# ---------------- LOGIN ---------------- #
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("Invalid credentials")

    st.stop()

st.success("Logged in successfully")

# ---------------- INPUT SECTION ---------------- #
st.markdown("### 🌐 Target Configuration")

colA, colB = st.columns(2)

with colA:
    url = st.text_input("Enter Target URL")

with colB:
    depth = st.slider("Crawl Depth", 1, 10, 3)

# ---------------- SCAN BUTTON ---------------- #
if st.button("🚀 Start Scan") and url:

    visited = set()
    results = {
        "xss": [],
        "sqli": [],
        "missing_headers": []
    }

    to_scan = [url]
    progress = st.progress(0)

    while to_scan and len(visited) < depth:
        current = to_scan.pop(0)

        if current not in visited:
            visited.add(current)

            form_results = scan_forms(current)
            results["xss"].extend(form_results["xss"])
            results["sqli"].extend(form_results["sqli"])

            results["missing_headers"] = check_headers(current)

            links = get_internal_links(current, url)
            to_scan.extend(links)

        progress.progress(min(len(visited) / depth, 1.0))

    risk, icon = calculate_risk(results)

    st.markdown("## 📊 Scan Results")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("XSS Found", len(results["xss"]))

    with col2:
        st.metric("SQL Injection Found", len(results["sqli"]))

    with col3:
        st.metric("Risk Level", f"{icon} {risk}")

    st.markdown("### 🛡 Missing Security Headers")
    st.write(results["missing_headers"])

    os.makedirs("data", exist_ok=True)
    with open("data/history.json", "w") as f:
        json.dump(results, f, indent=4)

    st.download_button(
        "📥 Download JSON Report",
        json.dumps(results, indent=4),
        "security_report.json"
    )