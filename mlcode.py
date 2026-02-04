import re
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

DATASET_PATH = "dataset2_converted.txt"

texts = []
labels = []

pattern = re.compile(r"\b(ham|spam)\b\s+(.*)", re.IGNORECASE)

with open(DATASET_PATH, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            labels.append(match.group(1).lower())
            texts.append(match.group(2).strip())

print("Total samples:", len(labels))
print("Ham:", labels.count("ham"))
print("Spam:", labels.count("spam"))

# --------------------------------------------------
# 1. TRAIN / VALIDATION SPLIT (80 / 20)
# --------------------------------------------------
X_train_text, X_val_text, y_train, y_val = train_test_split(
    texts,
    labels,
    test_size=0.2,
    stratify=labels,
    random_state=42
)

print("\nTrain samples:", len(y_train))
print("Validation samples:", len(y_val))

# --------------------------------------------------
# 2. TF-IDF (CONTROLLED TO AVOID OVERFITTING)
# --------------------------------------------------
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000,        # cap features → better generalization
    ngram_range=(1, 2),
    min_df=2,                 # ignore rare noise words
    max_df=0.9                # ignore overly common words
)

X_train = vectorizer.fit_transform(X_train_text)
X_val = vectorizer.transform(X_val_text)

# --------------------------------------------------
# 3. LOGISTIC REGRESSION (REGULARIZED)
# --------------------------------------------------
model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    C=1.0,                    # regularization strength
    solver="liblinear"
)

model.fit(X_train, y_train)

# --------------------------------------------------
# 4. TRAIN & VALIDATION ACCURACY
# --------------------------------------------------
train_pred = model.predict(X_train)
val_pred = model.predict(X_val)

train_acc = accuracy_score(y_train, train_pred)
val_acc = accuracy_score(y_val, val_pred)

print("\nTRAIN ACCURACY:", round(train_acc, 4))
print("VALIDATION ACCURACY:", round(val_acc, 4))

print("\nVALIDATION CLASSIFICATION REPORT:\n")
print(classification_report(y_val, val_pred))

# --------------------------------------------------
# 5. SAVE MODEL FILES (FOR GITHUB / TEAM)
# --------------------------------------------------
with open("spam_lr_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("tfidf_vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)  

print("\nModel and vectorizer saved successfully")
