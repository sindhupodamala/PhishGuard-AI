from flask import Flask, render_template, jsonify, request
import joblib
import sqlite3
from urllib.parse import urlparse
import ipaddress
import os

from database import create_database

app = Flask(__name__)

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "ml_model",
    "phishing_model.pkl"
)

model = joblib.load(MODEL_PATH)
create_database()


def get_threat_level(score):
    if score >= 65:
        return "High"
    elif score >= 30:
        return "Medium"
    return "Low"


def save_detection(email=None, url=None, result="",
                   confidence=0, threat_level="Low",
                   explanation=""):
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO detection_history
        (email, url, result, confidence, threat_level,
         risk_score, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        email, url, result, confidence,
        threat_level, confidence, explanation
    ))

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/history")
def history():
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM detection_history
        ORDER BY id DESC
    """)

    records = cursor.fetchall()
    conn.close()

    return render_template("history.html", records=records)


@app.route("/health")
def health():
    return jsonify({
        "message": "PhishGuard AI backend is running!",
        "status": "success"
    })


@app.route("/check-email", methods=["POST"])
def check_email():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()

    if not email:
        return jsonify({
            "result": "Please enter an email message",
            "explanation": "Email cannot be empty."
        }), 400

    prediction = model.predict([email])[0]
    probabilities = model.predict_proba([email])[0]

    phishing_probability = float(
        probabilities[list(model.classes_).index(1)]
    )

    score = round(phishing_probability * 100, 2)

    # Add warning signs from email content
    text = email.lower()
    reasons = []

    suspicious_phrases = [
        "verify your account",
        "account suspended",
        "urgent action",
        "click here",
        "enter your password",
        "share your otp",
        "confirm your bank",
        "claim your prize",
        "limited time",
        "send your details"
    ]

    for phrase in suspicious_phrases:
        if phrase in text:
            reasons.append("Suspicious phrase: " + phrase)

    if reasons:
        score = min(100, score + 20)

    threat_level = get_threat_level(score)

    if threat_level == "High":
        result = "Phishing Email"
    elif threat_level == "Medium":
        result = "Suspicious Email"
    else:
        result = "Legitimate Email"

    explanation = (
        "; ".join(reasons)
        if reasons else
        "Email assessed using the trained ML model."
    )

    save_detection(
        email=email,
        result=result,
        confidence=score,
        threat_level=threat_level,
        explanation=explanation
    )

    return jsonify({
        "result": result,
        "threat_level": threat_level,
        "risk_score": score,
        "confidence": score,
        "explanation": explanation
    })


@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "result": "Please enter a URL"
        }), 400

    parsed = urlparse(
        url if "://" in url else "https://" + url
    )

    hostname = parsed.hostname or ""
    reasons = []
    score = 0

    if parsed.scheme.lower() == "http":
        score += 20
        reasons.append("Website does not use HTTPS")

    if "@" in url:
        score += 25
        reasons.append("URL contains an unusual @ symbol")

    try:
        ipaddress.ip_address(hostname)
        score += 30
        reasons.append("URL uses an IP address")
    except ValueError:
        pass

    suspicious_words = [
        "verify", "login", "account",
        "update", "password", "bank",
        "secure", "free-gift", "prize",
        "suspended", "reset"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append("Suspicious keyword: " + word)

    if len(url) > 100:
        score += 10
        reasons.append("Unusually long URL")

    if hostname.count(".") >= 4:
        score += 15
        reasons.append("Too many subdomains")

    score = min(score, 100)
    threat_level = get_threat_level(score)

    if threat_level == "High":
        result = "Potentially Suspicious URL"
    elif threat_level == "Medium":
        result = "Suspicious URL"
    else:
        result = "No obvious warning signs detected"

    explanation = (
        "; ".join(reasons)
        if reasons else
        "No obvious warning signs found. This does not guarantee the URL is safe."
    )

    save_detection(
        url=url,
        result=result,
        confidence=score,
        threat_level=threat_level,
        explanation=explanation
    )

    return jsonify({
        "result": result,
        "threat_level": threat_level,
        "risk_score": score,
        "explanation": explanation
    })


@app.route("/stats")
def stats():
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM detection_history
        WHERE email IS NOT NULL AND email != ''
    """)
    total_emails = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM detection_history
        WHERE url IS NOT NULL AND url != ''
    """)
    total_urls = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM detection_history
        WHERE result = 'Phishing Email'
    """)
    phishing_emails = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM detection_history
        WHERE result = 'Suspicious Email'
    """)
    suspicious_emails = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM detection_history
        WHERE result = 'Legitimate Email'
    """)
    legitimate_emails = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM detection_history
        WHERE result IN (
            'Potentially Suspicious URL', 'Suspicious URL'
        )
    """)
    suspicious_urls = cursor.fetchone()[0]

    safe_urls = total_urls - suspicious_urls

    conn.close()

    return jsonify({
        "total_emails": total_emails,
        "total_urls": total_urls,
        "phishing_emails": phishing_emails,
        "suspicious_emails": suspicious_emails,
        "legitimate_emails": legitimate_emails,
        "suspicious_urls": suspicious_urls,
        "safe_urls": safe_urls
    })


if __name__ == "__main__":
    app.run(debug=True)