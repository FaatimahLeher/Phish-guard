# PhishGuard — Phishing Email Detector

An AI-powered phishing email detection web app that analyzes emails across 4 independent layers using machine learning and heuristic analysis.

[View Live Demo](#) <!-- update this once deployed -->

## Tech Stack
- Python
- Flask + Flask-CORS
- Scikit-learn (Random Forest, TF-IDF Vectorizer)
- BeautifulSoup4
- Vanilla JavaScript
- HTML/CSS

## How to Run

```bash
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train the ML model
python train_model.py

# 4. Start the backend
python app.py

# 5. Open index.html in your browser
```

## Features
- **4-Layer Detection Engine:**
  - Header Analysis — detects sender/Reply-To domain mismatches and display name spoofing
  - URL Analysis — flags suspicious TLDs, raw IP addresses, and URL shorteners
  - Content Heuristics — scans for urgent language, sensitive data requests, and reward lures
  - ML Classifier — Random Forest model trained on 18,000+ real phishing and safe emails (97% accuracy)
- Weighted scoring system combining all 4 layers into a single risk score
- `.eml` file upload — parses real email files and auto-fills the form
- Risk score gauge and per-layer score breakdown
- Color-coded red flag cards by severity
- Responsive landing page with smooth scroll navigation
