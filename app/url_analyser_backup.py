
from urllib.parse import urlparse


def analyze_url(url):
    reasons = []
    risk = "Low"

    # Add https:// if the user leaves out the protocol
    if "://" not in url:
        url = "https://" + url

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""

    # Check whether the URL looks valid
    if not hostname or "." not in hostname:
        return "Invalid", ["Please enter a valid-looking URL."]

    # Check for HTTPS
    if parsed_url.scheme != "https":
        reasons.append("The URL does not use HTTPS.")
        risk = "Medium"

    # Check for @ symbol
    if "@" in url:
        reasons.append("The URL contains an @ symbol.")
        risk = "High"

    # Check for unusually long URLs
    if len(url) > 100:
        reasons.append("The URL is unusually long.")
        if risk == "Low":
            risk = "Medium"

    # Check whether the hostname looks like an IPv4 address
    parts = hostname.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        reasons.append("The hostname uses an IP address instead of a domain name.")
        risk = "High"

    # Check for suspicious words in the URL
    suspicious_words = [
        "login", "verify", "account", "secure",
        "password", "update", "bank"
    ]

    lower_url = url.lower()
    found_words = [word for word in suspicious_words if word in lower_url]

    if found_words:
        reasons.append(
            "The URL contains potentially suspicious words: "
            + ", ".join(found_words)
        )
        if risk == "Low":
            risk = "Medium"

    # If no checks raised a warning
    if not reasons:
        reasons.append("No obvious warning signs were found by these basic checks.")

    return risk, reasons

