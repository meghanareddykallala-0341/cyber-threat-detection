
import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.dummy import DummyClassifier

# 1. Use the dataset stored inside this project
BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "datasets" / "phishing_features.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"

if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATASET_PATH}"
    )

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded:", DATASET_PATH)
print("Dataset shape:", df.shape)

features = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "special_char_count",
    "digits_count",
    "entropy",
]

required = features + ["label"]
missing = [c for c in required if c not in df.columns]

if missing:
    raise ValueError(f"Missing columns: {missing}")

# 2. Clean the numeric data
X = df[features].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan)

y = pd.to_numeric(df["label"], errors="coerce")

valid = y.isin([0, 1])
X = X.loc[valid].copy()
y = y.loc[valid].astype(int)

print("\nLabel counts:")
print("0 = Legitimate, 1 = Phishing")
print(y.value_counts().sort_index())

if y.nunique() != 2:
    raise ValueError("The dataset must contain both labels 0 and 1.")

# 3. Split the data before training
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

# 4. Baseline: always predict the most common training label
baseline = DummyClassifier(strategy="most_frequent")
baseline.fit(X_train, y_train)
baseline_predictions = baseline.predict(X_test)

print("\nMAJORITY-CLASS BASELINE")
print(classification_report(
    y_test,
    baseline_predictions,
    labels=[0, 1],
    target_names=["Legitimate", "Phishing"],
    zero_division=0,
))

# 5. Train the Random Forest pipeline
pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("model", RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )),
])

print("\nTraining Random Forest...")
pipeline.fit(X_train, y_train)

# 6. Evaluate both classes separately
predictions = pipeline.predict(X_test)

print("\nRANDOM FOREST RESULTS")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Legitimate", "Phishing"],
    zero_division=0,
))

print("Confusion matrix:")
print("Rows = actual; columns = predicted")
print("Order: Legitimate, Phishing")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

# 7. Save the model and feature order
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

joblib.dump(
    {
        "model": pipeline,
        "features": features,
    },
    MODEL_PATH,
)

print(f"\nModel saved: {MODEL_PATH}")
print("Evaluation finished.")
print(
    "Note: results on a random split do not prove "
    "reliability on new real-world URLs."
)

