
import pandas as pd

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    balanced_accuracy_score
)

# Load training dataset
path = Path("datasets") / "SILRAD" / "fasttext-trainmodel.csv"
df = pd.read_csv(path)

features = [col for col in df.columns if col != "class"]

X = df[features]
y = df["class"]

# Group identical feature vectors together
groups = pd.util.hash_pandas_object(
    X, index=False
)

# Split groups, not individual rows
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.2,
    random_state=42
)

train_idx, val_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_idx]
y_train = y.iloc[train_idx]

X_val = X.iloc[val_idx]
y_val = y.iloc[val_idx]

print("Training records:", len(X_train))
print("Validation records:", len(X_val))

# Verify no identical feature vectors cross the split
train_groups = set(groups.iloc[train_idx])
val_groups = set(groups.iloc[val_idx])

print(
    "Overlapping feature groups:",
    len(train_groups.intersection(val_groups))
)

# Train model
model = RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("\nTraining model...")
model.fit(X_train, y_train)

import pandas as pd

importance = pd.DataFrame({
    "Feature": X_train.columns,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTOP 20 IMPORTANT FEATURES:")
print(importance.head(20).to_string(index=False))


# Predict
predictions = model.predict(X_val)

print("\nClassification Report:")
print(classification_report(
    y_val,
    predictions,
    labels=[0, 1],
    target_names=["Goodware", "Ransomware"],
    zero_division=0
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_val, predictions, labels=[0, 1]))

print(
    "\nBalanced Accuracy:",
    round(balanced_accuracy_score(y_val, predictions) * 100, 2),
    "%"
)
