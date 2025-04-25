import streamlit as st
import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver
import pandas as pd
from difflib import SequenceMatcher

# Load the trained model
model = joblib.load("phishing_model.pkl")

# Cache DNS results
dns_cache = {}

# Suspicious TLDs
suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'site', 'xyz', 'buzz'}

# Popular brands to compare against
known_brands = ["paypal", "google", "apple", "microsoft", "wikipedia", "facebook", "instagram", "amazon", "netflix"]

# Function to check DNS record presence
def check_dns(domain, rtype):
    key = (domain, rtype)
    if key in dns_cache:
        return dns_cache[key]
    try:
        dns.resolver.resolve(domain, rtype, lifetime=2)
        dns_cache[key] = 1
    except:
        dns_cache[key] = 0
    return dns_cache[key]

# Function to detect brand lookalikes
def is_similar_to_known_brand(domain):
    for brand in known_brands:
        similarity = SequenceMatcher(None, domain, brand).ratio()
        if similarity > 0.75:
            return 1
    return 0

# Feature extraction
def extract_features(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    features = {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'digit_count': sum(c.isdigit() for c in url),
        'is_https': int(url.startswith('https')),
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'domain_suffix': pd.Series([ext.suffix]).astype("category").cat.codes[0],
        'has_a_record': check_dns(domain, 'A'),
        'has_mx_record': check_dns(domain, 'MX'),
        'suspicious_tld': int(ext.suffix in suspicious_tlds),
        'brand_similarity': is_similar_to_known_brand(ext.domain),
    }

    return pd.DataFrame([features])

# Prediction logic
def predict_url(url):
    features = extract_features(url)
    phishing_proba = model.predict_proba(features)[0][1]

    if phishing_proba > 0.6:
        return f"🚨 Phishing (Confidence: {phishing_proba * 100:.2f}%)"
    elif phishing_proba > 0.4:
        return f"⚠️ Suspicious (Confidence: {phishing_proba * 100:.2f}%)"
    else:
        return f"✅ Legitimate (Confidence: {(1 - phishing_proba) * 100:.2f}%)"

# Streamlit UI
st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️")
st.title("🛡️ Phishing URL Detector")
st.write("Enter a URL to check if it's phishing or legitimate.")

url_input = st.text_input("🔗 Enter URL:")
if st.button("🔍 Verify"):
    if url_input:
        result = predict_url(url_input)
        st.success(result)
    else:
        st.warning("Please enter a URL.")
