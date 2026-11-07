
import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    balanced_accuracy_score
)

# Project paths
DATASET_DIR = Path("datasets") / "SILRAD"
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

# Load datasets
train = pd.read_csv(DATASET_DIR / "fasttext-trainmodel.csv")
test = pd.read_csv(DATASET_DIR / "fasttext-testmodel.csv")

# Separate features and labels
feature_columns = [col for col in train.columns if col != "class"]

X_train = train[feature_columns]
y_train = train["class"]

# Find feature vectors shared by training and testing
train_hashes = pd.util.hash_pandas_object(
    X_train, index=False
)

test_hashes = pd.util.hash_pandas_object(
    test[feature_columns], index=False
)

overlap_hashes = set(train_hashes)

# Remove overlapping feature vectors from testing
clean_mask = ~test_hashes.isin(overlap_hashes)

clean_test = test.loc[clean_mask].copy()

X_test = clean_test[feature_columns]
y_test = clean_test["class"]

print("Training records:", len(X_train))
print("Original testing records:", len(test))
print("Testing records after overlap removal:", len(X_test))

# Train model
model = RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("\nTraining ransomware detection model...")
model.fit(X_train, y_train)

# Evaluate
predictions = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Goodware", "Ransomware"]
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

print(
    "\nBalanced Accuracy:",
    round(balanced_accuracy_score(y_test, predictions) * 100, 2),
    "%"
)

# Save model and feature order
model_data = {
    "model": model,
    "features": feature_columns
}

model_path = MODEL_DIR / "ransomware_model.joblib"
joblib.dump(model_data, model_path)

print("\nModel saved successfully:", model_path)
