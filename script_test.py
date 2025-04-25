import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver
from difflib import SequenceMatcher

# Load model and feature names
model = joblib.load("phishing_model.pkl")
feature_names = joblib.load("model_features.pkl")

# DNS cache
dns_cache = {}

# Suspicious TLDs and brand list
suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'site', 'xyz', 'buzz'}
known_brands = ["paypal", "google", "apple", "microsoft", "wikipedia", "facebook", "instagram", "amazon", "netflix"]

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

def is_similar_to_known_brand(domain):
    for brand in known_brands:
        similarity = SequenceMatcher(None, domain, brand).ratio()
        if similarity > 0.75:
            return 1
    return 0

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
        'subdomain_depth': parsed.netloc.count('.') - 1,
    }

    # Ensure all expected features are present and ordered as per model's feature names
    feature_vector = [features.get(feat, 0) for feat in feature_names]  # Default to 0 if feature is missing
    return pd.DataFrame([feature_vector], columns=feature_names)

# --- Streamlit App UI ---
st.title("🔍 Phishing URL Detector")

url_input = st.text_input("Enter a URL to verify")

if st.button("Verify"):
    if url_input.strip() == "":
        st.warning("Please enter a valid URL.")
    else:
        try:
            input_df = extract_features(url_input)
            phishing_proba = model.predict_proba(input_df)[0][1]

            if phishing_proba > 0.6:
                st.error(f"🚨 Phishing Detected!")
            elif phishing_proba > 0.4:
                st.warning(f"⚠️ Suspicious Link!")
            else:
                st.success(f"✅ Legitimate Link")

        except Exception as e:
            st.error(f"Error analyzing the URL: {e}")
