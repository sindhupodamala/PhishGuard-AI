import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report

# Get project folder path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load dataset
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")

data = pd.read_csv(DATASET_PATH)

# Check dataset columns
if not {"email", "label"}.issubset(data.columns):
    raise ValueError("Dataset must contain email and label columns.")

# Remove empty rows
data = data.dropna(subset=["email", "label"])

# Separate email text and labels
X = data["email"].astype(str)
y = data["label"].astype(int)

# Check labels
if set(y.unique()) != {0, 1}:
    raise ValueError("Dataset must contain labels 0 and 1.")

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# Create machine learning pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        lowercase=True,
        sublinear_tf=True
    )),
    ("classifier", MultinomialNB(alpha=0.5))
])

# Train model
model.fit(X_train, y_train)

# Test model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("PhishGuard AI Training Completed!")
print("Total Dataset Rows:", len(data))
print("Model Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Legitimate", "Phishing"],
    zero_division=0
))

# Save trained model
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

joblib.dump(model, MODEL_PATH)

print("\nModel saved successfully!")
