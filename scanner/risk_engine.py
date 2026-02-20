def calculate_risk(results):
    total = len(results["xss"]) + len(results["sqli"]) + len(results["missing_headers"])

    if total == 0:
        return "Low", "🟢"
    elif total <= 3:
        return "Medium", "🟡"
    elif total <= 6:
        return "High", "🟠"
    else:
        return "Critical", "🔴"