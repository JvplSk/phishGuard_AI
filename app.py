from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import ipaddress
import re
import joblib
from pathlib import Path

app = Flask(__name__)
MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.joblib"
model = joblib.load(MODEL_PATH)

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "signin", "confirm", "bank", "password", "wallet",
    "recover", "unlock", "support", "billing", "payment"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "cutt.ly", "is.gd", "buff.ly"
}


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze(url):
    raw = url.strip()

    normalized = raw if re.match(r"^https?://", raw, re.I) else "http://" + raw
    parsed = urlparse(normalized)

    host = parsed.hostname or ""
    host = host.lower()
    full = normalized.lower()

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    labels = [x for x in host.split(".") if x]
    subdomains = max(0, len(labels) - 2)

    suspicious_word_hits = [
        word for word in SUSPICIOUS_WORDS
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", full)
    ]

    special_chars = len(re.findall(r"[^a-zA-Z0-9:/?&.=_%#-]", raw))
    digit_count = sum(c.isdigit() for c in raw)
    hyphen_count = raw.count("-")
    dot_count = raw.count(".")
    query_params = len([x for x in query.split("&") if x])
    path_depth = len([x for x in path.split("/") if x])

    has_punycode = any(label.startswith("xn--") for label in labels)
    has_port = parsed.port is not None
    has_at = "@" in raw
    has_double_slash = "//" in path
    has_ip = is_ip_address(host)
    uses_https = parsed.scheme.lower() == "https"
    is_shortener = host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS)

    # Explainable heuristic risk engine.
    score = 0
    reasons = []
    positive_checks = []

    checks = [
        (has_ip, 22, "IP address used instead of a normal domain."),
        (not uses_https, 8, "Connection does not use HTTPS."),
        (has_at, 22, "The URL contains an @ symbol."),
        (is_shortener, 15, "A URL-shortening service is being used."),
        (len(raw) > 100, 10, "The URL is unusually long."),
        (len(raw) > 180, 7, "The URL is extremely long."),
        (subdomains >= 3, 10, "The hostname contains many subdomains."),
        (subdomains >= 5, 7, "The hostname contains an unusually deep subdomain chain."),
        (hyphen_count >= 3, 7, "The URL contains several hyphens."),
        (len(suspicious_word_hits) >= 2, 12, "Multiple security-sensitive keywords appear in the URL."),
        (has_double_slash, 7, "A double-slash pattern appears inside the path."),
        (has_punycode, 15, "Punycode/IDN encoding is present in the hostname."),
        (has_port, 5, "A non-default explicit port is present."),
        (special_chars >= 4, 5, "The URL contains several unusual special characters."),
        (digit_count >= 8, 5, "The URL contains an unusually high number of digits."),
        (query_params >= 5, 4, "The URL contains many query parameters."),
        (path_depth >= 6, 4, "The URL has a deep path structure.")
    ]

    for condition, points, message in checks:
        if condition:
            score += points
            reasons.append(message)

    score = min(100, score)

    # Small positive signals are kept separate from risk signals.
    if uses_https:
        positive_checks.append("HTTPS is enabled.")
    if not has_ip:
        positive_checks.append("A domain hostname is being used.")
    if len(raw) <= 100:
        positive_checks.append("URL length is within the normal threshold.")

    if score >= 65:
        label = "POTENTIAL PHISHING"
        threat = "HIGH"
    elif score >= 35:
        label = "SUSPICIOUS"
        threat = "MEDIUM"
    else:
        label = "LIKELY LEGITIMATE"
        threat = "LOW"

    # This is a heuristic confidence indicator, not a statistical ML probability.
    if threat == "HIGH":
        confidence = min(98, 70 + round(score * 0.25))
    elif threat == "MEDIUM":
        confidence = min(93, 62 + round(score * 0.35))
    else:
        confidence = min(94, 90 - round(score * 0.25))

    if not reasons:
        reasons = ["No strong suspicious URL-structure indicators were detected."]

    feature_rows = [
        {"name": "HTTPS", "value": "Enabled" if uses_https else "Not enabled",
         "status": "good" if uses_https else "warning"},
        {"name": "IP address", "value": "Detected" if has_ip else "Not detected",
         "status": "warning" if has_ip else "good"},
        {"name": "Subdomains", "value": str(subdomains),
         "status": "warning" if subdomains >= 3 else "good"},
        {"name": "URL length", "value": f"{len(raw)} chars",
         "status": "warning" if len(raw) > 100 else "good"},
        {"name": "Hyphens", "value": str(hyphen_count),
         "status": "warning" if hyphen_count >= 3 else "good"},
        {"name": "Sensitive keywords", "value": str(len(suspicious_word_hits)),
         "status": "warning" if len(suspicious_word_hits) >= 2 else "good"},
        {"name": "Shortener", "value": "Detected" if is_shortener else "Not detected",
         "status": "warning" if is_shortener else "good"},
        {"name": "Punycode", "value": "Detected" if has_punycode else "Not detected",
         "status": "warning" if has_punycode else "good"},
        {"name": "Query parameters", "value": str(query_params),
         "status": "warning" if query_params >= 5 else "good"},
    ]
    ml_prediction = int(model.predict([raw])[0])

    return {
        "label": label,
        "threat": threat,
        "confidence": confidence,
        "risk": score,
        "host": host or "Unknown",
        "url": raw,
        "https": uses_https,
        "length": len(raw),
        "reasons": reasons,
        "positive_checks": positive_checks,
        "features": feature_rows,
        "keyword_hits": suspicious_word_hits,
        "analysis_type": "Explainable URL heuristic analysis",
        "model_status": "ML model connected",
        "ml_prediction": ml_prediction
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/scan")
def scan():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify(error="Please enter a URL."), 400

    if len(url) > 2048:
        return jsonify(error="URL is too long. Maximum length is 2048 characters."), 400

    try:
        parsed = urlparse(
            url if re.match(r"^https?://", url, re.I) else "http://" + url
        )

        if not parsed.hostname:
            return jsonify(error="Please enter a valid domain or URL."), 400

        return jsonify(analyze(url))
    except ValueError:
        return jsonify(error="The URL contains an invalid port or hostname."), 400
    except Exception:
        return jsonify(error="Unable to analyze this URL."), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
