import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle

# ---- LOAD DATA ----
print("Loading dataset...")
df = pd.read_csv('Phishing_Email.csv')

# ---- CLEAN & PREPARE ----
print("Preparing data...")
# Drop the index column Kaggle added, rename columns for clarity
df = df.drop(columns=['Unnamed: 0'])
df = df.rename(columns={'Email Text': 'text', 'Email Type': 'label'})

# Drop any rows where text or label is missing
df = df.dropna(subset=['text', 'label'])

# Convert text labels to binary numbers: 1 = phishing, 0 = safe
df['label'] = (df['label'] == 'Phishing Email').astype(int)

print(f"Dataset size: {len(df)} emails")
print(f"Phishing: {df['label'].sum()} | Legitimate: {(df['label'] == 0).sum()}")

# ---- SPLIT ----
X = df['text']
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ---- VECTORIZE ----
print("Vectorizing text with TF-IDF...")
vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words='english',
    ngram_range=(1, 2),
    sublinear_tf=True
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)

# ---- TRAIN ----
print("Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
model.fit(X_train_vec, y_train)

# ---- EVALUATE ----
print("\n---- Model Performance ----")
y_pred = model.predict(X_test_vec)
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# ---- SAVE ----
print("Saving model...")
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

print("Done! model.pkl and vectorizer.pkl saved.")
