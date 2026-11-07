
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import traceback
import uuid


# Find the project directory
PROJECT_DIR = Path(__file__).resolve().parent.parent

# Load the trained ransomware model
MODEL_PATH = PROJECT_DIR / "models" / "ransomware_model_without_processguid.joblib"
REPORT_DIR = PROJECT_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)
model = joblib.load(MODEL_PATH)

# Get the model's expected feature names
FEATURE_NAMES = list(model.feature_names_in_)


def analyze_ransomware_csv(file_path):

    try:
        # Read CSV file
        df = pd.read_csv(file_path)

        if df.empty:
            raise ValueError("The uploaded CSV is empty.")

        # Check required columns
        missing_features = [
            feature for feature in FEATURE_NAMES
            if feature not in df.columns
        ]

        if missing_features:
            raise ValueError(
                "Missing SILRAD features: " + ", ".join(missing_features)
            )

        # Select the required features
        X = df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce")

        # Check for invalid values
        if X.isnull().any().any():
            raise ValueError("The CSV contains missing or non-numeric values.")

        if not np.isfinite(X.to_numpy()).all():
            raise ValueError("The CSV contains infinite values.")
        probabilities = model.predict_proba(X)

# Get the probability of the ransomware class (1)
        ransomware_class_index = list(model.classes_).index(1)
        ransomware_probabilities = probabilities[:, ransomware_class_index]
        predictions = (ransomware_probabilities >= 0.4).astype(int)

        # Count predictions
        goodware_count = int(np.sum(predictions == 0))
        ransomware_count = int(np.sum(predictions == 1))

                # Find the five records with the highest ransomware scores
        top_indices = np.argsort(ransomware_probabilities)[-5:][::-1]

        sample_results = []

        for i in top_indices:
            sample_results.append({
                "record": int(i) + 1,
                "prediction": (
                    "Ransomware" if predictions[i] == 1 else "Goodware"
                ),
                "ransomware_probability": round(
                    float(ransomware_probabilities[i]) * 100, 2
                )
            })
                    # Create a report containing all analysed records
        report_df = df.copy()

        report_df["Predicted_Class"] = np.where(
            predictions == 1,
            "Ransomware",
            "Goodware"
        )

        report_df["Ransomware_Probability_Percent"] = np.round(
            ransomware_probabilities * 100, 2
        )

        report_df["Classification_Threshold"] = 0.4

        # Generate a unique report filename
        report_filename = (
            f"ransomware_report_{uuid.uuid4().hex[:10]}.csv"
        )

        report_path = REPORT_DIR / report_filename

        report_df.to_csv(report_path, index=False)

        return {
            "status": "Success",
            "message": "SILRAD event analysis completed successfully.",
            "total_records": len(predictions),
            "goodware_count": goodware_count,
            "ransomware_count": ransomware_count,
            "sample_results": sample_results,
            "report_filename": report_filename,
            "details": [
                "Model: SILRAD Random Forest classifier",
                f"Features used: {len(FEATURE_NAMES)}",
                "Classification threshold: 0.4",
                f"Goodware events: {goodware_count}",
                f"Ransomware events: {ransomware_count}"
            ]
        }

    except Exception as error:
        import traceback
        traceback.print_exc()

        return {
            "status": "Invalid",
            "message": str(error),
            "total_records": 0,
            "goodware_count": 0,
            "ransomware_count": 0,
            "sample_results": [],
            "details": []
        }
