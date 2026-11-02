
from urllib.parse import urlparse
from pathlib import Path
import ipaddress
import math
import string

import joblib
import pandas as pd


# Load the trained model
MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "models"
    / "phishing_model.joblib"
)

saved_model = joblib.load(MODEL_PATH)
model = saved_model["model"]
features = saved_model["features"]

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "password",
    "update",
    "bank",
]


def calculate_entropy(text):
    """Calculate the character entropy of a string."""
    if not text:
        return 0.0

    entropy = 0.0

    for character in set(text):
        probability = text.count(character) / len(text)
        entropy -= probability * math.log2(probability)

    return entropy


def extract_features(url):
    """Extract the numeric features expected by the model."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    lower_url = url.lower()

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "num_subdirs": (
            len([part for part in path.split("/") if part])
            if parsed.netloc
            else 0
        ),
        "num_params": len(parsed.query.split("&")) if parsed.query else 0,
        "suspicious_words": sum(
            1 for word in SUSPICIOUS_WORDS if word in lower_url
        ),
        "special_char_count": max(
            0,
            sum(
                1 for character in url
                if character in string.punctuation
            ) - url.count("."),
        ),
        "digits_count": sum(character.isdigit() for character in url),
        "entropy": calculate_entropy(url),
    }


def analyze_url(url):
    """Return a risk level and explanations for a submitted URL."""
    if not isinstance(url, str) or not url.strip():
        return "Invalid", ["Please enter a URL."]

    url = url.strip()

    # Add a scheme only when the user did not provide one.
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if (
        parsed.scheme.lower() not in ("http", "https")
        or not hostname
        or "." not in hostname
        or any(character.isspace() for character in url)
    ):
        return "Invalid", ["Please enter a valid-looking HTTP or HTTPS URL."]

    # Use the same normalized URL for parsing and feature extraction.
    feature_values = extract_features(url)

    input_values = pd.DataFrame(
        [[feature_values[name] for name in features]],
        columns=features,
    )

    prediction = int(model.predict(input_values)[0])
    probabilities = model.predict_proba(input_values)[0]
    confidence = float(max(probabilities)) * 100

    reasons = [
        "Machine-learning model prediction: "
        + ("Phishing." if prediction == 1 else "Legitimate."),
        (
            f"Model confidence: {confidence:.1f}%. "
            "This is not a guarantee of safety."
        ),
    ]

    # Start with the model's result.
    risk = "High" if prediction == 1 else "Low"

    # Warning signs increase the displayed risk but do not prove phishing.
    if parsed.scheme.lower() != "https":
        risk = "High"
        reasons.append("The URL uses HTTP rather than HTTPS.")

    if "@" in url:
        risk = "High"
        reasons.append("The URL contains an @ symbol.")

    try:
        ipaddress.ip_address(hostname)
        risk = "High"
        reasons.append(
            "The hostname is an IP address rather than a domain name."
        )
    except ValueError:
        pass

    suspicious_found = [
        word for word in SUSPICIOUS_WORDS if word in url.lower()
    ]

    if suspicious_found:
        risk = "High"
        reasons.append(
            "Potentially suspicious words found: "
            + ", ".join(suspicious_found)
            + ". These words alone do not prove phishing."
        )

    if prediction == 1:
        reasons.append(
            "The model detected patterns associated with phishing URLs."
        )
    else:
        reasons.append(
            "The model classified this URL as legitimate, "
            "but it may still be unsafe."
        )

    return risk, reasons
