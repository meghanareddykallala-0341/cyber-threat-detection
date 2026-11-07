
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Project paths
PROJECT_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    PROJECT_DIR / "models" /
    "ransomware_model_without_processguid.joblib"
)

TEST_PATH = (
    PROJECT_DIR / "datasets" / "SILRAD" /
    "fasttext-testmodel.csv"
)

# Load trained model
model = joblib.load(MODEL_PATH)

FEATURE_NAMES = list(model.feature_names_in_)

# Load test dataset
df = pd.read_csv(TEST_PATH)

print("Test dataset shape:", df.shape)

# Separate features and actual labels
X = df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce")
y = pd.to_numeric(df["class"])

if X.isnull().any().any():
    raise ValueError("Test data contains missing or invalid features.")

if not np.isfinite(X.to_numpy()).all():
    raise ValueError("Test data contains infinite values.")

# Get ransomware probabilities
probabilities = model.predict_proba(X)

ransomware_class_index = list(model.classes_).index(1)

ransomware_probabilities = probabilities[:, ransomware_class_index]

# Apply selected threshold
threshold = 0.4
predictions = (ransomware_probabilities >= threshold).astype(int)

# Calculate evaluation metrics
print("\nRANSOMWARE MODEL EVALUATION")
print("Threshold:", threshold)

print("\nAccuracy:",
      round(accuracy_score(y, predictions), 4))

print("Balanced Accuracy:",
      round(balanced_accuracy_score(y, predictions), 4))

print("Precision:",
      round(precision_score(y, predictions, zero_division=0), 4))

print("Recall:",
      round(recall_score(y, predictions, zero_division=0), 4))

print("F1-score:",
      round(f1_score(y, predictions, zero_division=0), 4))

print("\nConfusion Matrix:")
print(confusion_matrix(y, predictions))

print("\nClassification Report:")
print(classification_report(
    y,
    predictions,
    target_names=["Goodware", "Ransomware"],
    zero_division=0
))
