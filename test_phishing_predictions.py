
import joblib
import pandas as pd

saved = joblib.load("models/phishing_model.joblib")
model = saved["model"]
features = saved["features"]

# Example feature values for testing the prediction pipeline.
# These are illustrative values, not verified measurements
# extracted from the example URLs.
test_urls = [
    {
        "name": "Example A",
        "url_length": 15,
        "num_dots": 1,
        "has_https": 1,
        "has_ip": 0,
        "num_subdirs": 0,
        "num_params": 0,
        "suspicious_words": 0,
        "special_char_count": 0,
        "digits_count": 0,
        "entropy": 3.0,
    },
    {
        "name": "Example B",
        "url_length": 80,
        "num_dots": 4,
        "has_https": 0,
        "has_ip": 0,
        "num_subdirs": 5,
        "num_params": 2,
        "suspicious_words": 2,
        "special_char_count": 5,
        "digits_count": 20,
        "entropy": 4.8,
    },
]

for item in test_urls:
    name = item.pop("name")
    X = pd.DataFrame([item])[features]
    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]
    confidence = float(max(probabilities)) * 100

    print(f"\n{name}")
    print("Predicted label:", prediction)
    print("Interpretation:", "Phishing" if prediction == 1 else "Legitimate")
    print(f"Model confidence: {confidence:.2f}%")
