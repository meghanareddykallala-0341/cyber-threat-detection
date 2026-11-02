
import joblib
import pandas as pd

model_data = joblib.load("models/phishing_model.joblib")

model = model_data["model"]
features = model_data["features"]

importance = pd.DataFrame({
    "Feature": features,
    "Importance": model.feature_importances_,
})

importance = importance.sort_values(
    by="Importance",
    ascending=False,
)

print("PHISHING MODEL FEATURE IMPORTANCE")
print(importance.to_string(index=False))

print("\nModel classes:", model.classes_)
print("\nSaved feature order:", features)
