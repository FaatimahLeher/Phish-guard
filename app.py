from flask import Flask, request, jsonify
from flask_cors import CORS
from bs4 import BeautifulSoup
import re
import pickle
import numpy as np

app = Flask(__name__)
CORS(app)


# ---- LOAD ML MODEL ----
print("Loading ML model...")
with open('model.pkl', 'rb') as f:
    ml_model = pickle.load(f)

with open('vectorizer.pkl', 'rb') as f:
    ml_vectorizer = pickle.load(f)

print("Model loaded successfully!")


# ---- URL ANALYSIS ----

SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.loan']
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'cutt.ly']
SUSPICIOUS_KEYWORDS_IN_URL = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'banking']

def extract_urls(text):
    return re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)

def analyze_urls(urls):
    flags = []
    score = 0

    for url in urls:
        url_lower = url.lower()

        for shortener in URL_SHORTENERS:
            if shortener in url_lower:
                score += 15
                flags.append({ "layer": "URL", "severity": "high", "text": f"URL shortener detected: {shortener}" })

        for tld in SUSPICIOUS_TLDS:
            if url_lower.endswith(tld) or (tld + '/') in url_lower:
                score += 15
                flags.append({ "layer": "URL", "severity": "high", "text": f"Suspicious TLD detected: {tld}" })

        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 20
            flags.append({ "layer": "URL", "severity": "high", "text": "URL uses raw IP address instead of domain name" })

        for keyword in SUSPICIOUS_KEYWORDS_IN_URL:
            if keyword in url_lower:
                score += 10
                flags.append({ "layer": "URL", "severity": "medium", "text": f"Suspicious keyword in URL: '{keyword}'" })

    return score, flags


# ---- HEADER ANALYSIS ----

def analyze_headers(sender, reply_to, subject):
    flags = []
    score = 0

    if sender and reply_to:
        sender_domain = sender.split('@')[-1].lower().strip('>')
        reply_domain  = reply_to.split('@')[-1].lower().strip('>')
        if sender_domain != reply_domain:
            score += 25
            flags.append({ "layer": "Header", "severity": "high", "text": f"Sender domain ({sender_domain}) doesn't match Reply-To ({reply_domain})" })

    free_domains     = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    official_keywords = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'bank', 'netflix']

    if sender:
        sender_lower = sender.lower()
        domain_part  = sender_lower.split('@')[-1].strip('>')
        is_free      = any(d in domain_part for d in free_domains)
        looks_official = any(k in sender_lower or k in subject.lower() for k in official_keywords)

        if is_free and looks_official:
            score += 25
            flags.append({ "layer": "Header", "severity": "high", "text": f"Official-looking email sent from free domain ({domain_part})" })

        if '<' in sender:
            display_name = sender.split('<')[0].lower()
            domain = sender.split('@')[-1].lower().strip('>')
            for keyword in official_keywords:
                if keyword in display_name and keyword not in domain:
                    score += 20
                    flags.append({ "layer": "Header", "severity": "high", "text": f"Display name mentions '{keyword}' but domain doesn't match" })

    return score, flags


# ---- HEURISTICS ANALYSIS ----

URGENT_PHRASES    = ["act now", "urgent", "immediate action", "within 24 hours", "account suspended",
                     "account closed", "verify immediately", "limited time", "expires soon",
                     "final notice", "your account will be"]
SENSITIVE_PHRASES = ["enter your password", "confirm your password", "social security",
                     "credit card", "bank account", "date of birth", "mother's maiden name",
                     "verify your identity", "update your billing", "enter your details"]
GREED_PHRASES     = ["you have won", "you've won", "claim your prize", "free gift",
                     "congratulations", "you were selected", "you have been chosen",
                     "special reward", "$1000", "$500", "cash prize"]

def analyze_heuristics(text):
    flags = []
    score = 0
    text_lower = text.lower()

    for phrase in URGENT_PHRASES:
        if phrase in text_lower:
            score += 12
            flags.append({ "layer": "Heuristics", "severity": "high", "text": f"Urgent language: \"{phrase}\"" })

    for phrase in SENSITIVE_PHRASES:
        if phrase in text_lower:
            score += 18
            flags.append({ "layer": "Heuristics", "severity": "high", "text": f"Requests sensitive info: \"{phrase}\"" })

    for phrase in GREED_PHRASES:
        if phrase in text_lower:
            score += 10
            flags.append({ "layer": "Heuristics", "severity": "medium", "text": f"Reward/greed language: \"{phrase}\"" })

    caps_words = re.findall(r'\b[A-Z]{3,}\b', text)
    if len(caps_words) > 5:
        score += 10
        flags.append({ "layer": "Heuristics", "severity": "medium", "text": f"Excessive capital letters ({len(caps_words)} all-caps words)" })

    exclamations = text.count('!')
    if exclamations > 3:
        score += 8
        flags.append({ "layer": "Heuristics", "severity": "medium", "text": f"Too many exclamation marks ({exclamations} found)" })

    return score, flags


# ---- ML ANALYSIS ----

def analyze_ml(text):
    flags = []
    score = 0

    text_vec   = ml_vectorizer.transform([text])
    prediction = ml_model.predict(text_vec)[0]
    probability = ml_model.predict_proba(text_vec)[0]
    phishing_confidence = round(probability[1] * 100, 1)

    if prediction == 1:
        score = int((phishing_confidence / 100) * 40)
        flags.append({
            "layer": "ML Model",
            "severity": "high" if phishing_confidence > 75 else "medium",
            "text": f"ML classifier flagged as phishing ({phishing_confidence}% confidence)"
        })
    else:
        flags.append({
            "layer": "ML Model",
            "severity": "low",
            "text": f"ML classifier says legitimate ({round(probability[0] * 100, 1)}% confidence)"
        })

    return score, flags


# ---- WEIGHTED SCORING ----

WEIGHTS = {
    "header":     0.30,
    "heuristics": 0.25,
    "url":        0.25,
    "ml":         0.20
}

def calculate_weighted_score(header_score, heuristic_score, url_score, ml_score):
    weighted = (
        (min(header_score, 100)     * WEIGHTS["header"])     +
        (min(heuristic_score, 100)  * WEIGHTS["heuristics"]) +
        (min(url_score, 100)        * WEIGHTS["url"])        +
        (min(ml_score, 100)         * WEIGHTS["ml"])
    )
    # boost: if two or more layers fire, add a combo penalty
    layers_fired = sum(1 for s in [header_score, heuristic_score, url_score, ml_score] if s > 0)
    bonus = (layers_fired - 1) * 8 if layers_fired > 1 else 0
    return min(int(weighted) + bonus, 100)


# ---- EML PARSER ROUTE ----

import email as email_lib
from email import policy

@app.route('/parse-eml', methods=['POST'])
def parse_eml():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    raw = request.files['file'].read()
    msg = email_lib.message_from_bytes(raw, policy=policy.default)

    sender   = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    subject  = msg.get('Subject', '')

    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain' and 'attachment' not in str(part.get('Content-Disposition', '')):
                body = part.get_content()
                break
        if not body:
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    body = BeautifulSoup(part.get_content(), 'html.parser').get_text()
                    break
    else:
        body = msg.get_content()

    return jsonify({
        "sender":   sender,
        "reply_to": reply_to,
        "subject":  subject,
        "body":     body.strip()
    })


# ---- MAIN ROUTE ----

@app.route('/analyze', methods=['POST'])
def analyze():
    data     = request.get_json()
    sender   = data.get('sender', '')
    reply_to = data.get('reply_to', '')
    subject  = data.get('subject', '')
    body     = data.get('body', '')

    soup       = BeautifulSoup(body, 'html.parser')
    clean_body = soup.get_text()
    full_text  = subject + ' ' + clean_body

    url_score,       url_flags       = analyze_urls(extract_urls(clean_body))
    header_score,    header_flags    = analyze_headers(sender, reply_to, subject)
    heuristic_score, heuristic_flags = analyze_heuristics(full_text)
    ml_score,        ml_flags        = analyze_ml(full_text)

    total_score = calculate_weighted_score(header_score, heuristic_score, url_score, ml_score)
    all_flags   = header_flags + heuristic_flags + url_flags + ml_flags

    if total_score >= 45:
        verdict = "phishing"
    elif total_score >= 20:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return jsonify({
        "score":   total_score,
        "verdict": verdict,
        "flags":   all_flags,
        "breakdown": {
            "header":     header_score,
            "heuristics": heuristic_score,
            "url":        url_score,
            "ml":         ml_score
        }
    })


if __name__ == '__main__':
    app.run(debug=True)