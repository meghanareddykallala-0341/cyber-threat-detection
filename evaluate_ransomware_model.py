
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)


# Project paths
PROJECT_DIR = Path(__file__).resolve().parent
MODEL_PATH = PROJECT_DIR / "models" / "ransomware_model_without_processguid.joblib"
DATASET_PATH = PROJECT_DIR / "datasets" / "SILRAD" / "fasttext-testmodel.csv"


# Load model and test dataset
print("Loading model...")
model = joblib.load(MODEL_PATH)

print("Loading test dataset...")
df = pd.read_csv(DATASET_PATH)


# Separate input features and actual labels
FEATURE_NAMES = list(model.feature_names_in_)

X_test = df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce")
y_actual = df["class"].astype(int)

if X_test.isnull().any().any():
    raise ValueError("Test data contains missing or invalid feature values.")


# Generate predictions
print("Generating predictions...")
y_predicted = model.predict(X_test)


# Calculate evaluation metrics
print("\n========== RANSOMWARE MODEL EVALUATION ==========")

print("\nTotal test records:", len(y_actual))

print("\nAccuracy:", round(accuracy_score(y_actual, y_predicted) * 100, 2), "%")

print(
    "Balanced Accuracy:",
    round(balanced_accuracy_score(y_actual, y_predicted) * 100, 2),
    "%"
)

print(
    "Precision:",
    round(precision_score(y_actual, y_predicted, pos_label=1) * 100, 2),
    "%"
)

print(
    "Recall:",
    round(recall_score(y_actual, y_predicted, pos_label=1) * 100, 2),
    "%"
)

print(
    "F1 Score:",
    round(f1_score(y_actual, y_predicted, pos_label=1) * 100, 2),
    "%"
)


# Detailed classification report
print("\nClassification Report:")
print(
    classification_report(
        y_actual,
        y_predicted,
        labels=[0, 1],
        target_names=["Goodware", "Ransomware"],
        zero_division=0
    )
)


# Confusion matrix
print("Confusion Matrix:")
print(confusion_matrix(y_actual, y_predicted, labels=[0, 1]))

print("\nEvaluation completed.")
