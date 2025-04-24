import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver
import pandas as pd
import streamlit as st


model = joblib.load("phishing_model_updated.pkl")
with open("model_features.txt", "r") as f:
    expected_columns = f.read().splitlines()


dns_cache = {}

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


trusted_domains = ["paypal.com", "google.com", "microsoft.com", "apple.com"]
suspicious_hosts = ["trycloudflare.com", "glitch.me", "replit.dev", "web.app"]

def predict_url(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain_parts = ext.subdomain.split('.')

   
    if any(t in domain for t in trusted_domains):
        return "✅ Legitimate (Whitelisted)"

    
    if domain in suspicious_hosts and len(subdomain_parts) >= 2:
        return f"🚨 Phishing (Suspicious subdomain on {domain})"

   
    features = {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'digit_count': sum(c.isdigit() for c in url),
        'is_https': int(url.startswith('https')),
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'subdomain_depth': len(subdomain_parts),
        'domain_suffix': pd.Series([ext.suffix]).astype("category").cat.codes[0],
        'has_a_record': check_dns(domain, 'A'),
        'has_mx_record': check_dns(domain, 'MX')
    }

 
    input_df = pd.DataFrame([features])
    input_df = input_df.reindex(columns=expected_columns)

    phishing_proba = model.predict_proba(input_df)[0][1]

    if phishing_proba > 0.6:
        return f"🚨 Phishing (Confidence: {phishing_proba * 100:.2f}%)"
    elif phishing_proba > 0.4:
        return f"⚠️ Suspicious (Confidence: {phishing_proba * 100:.2f}%)"
    else:
        return f"✅ Legitimate (Confidence: { (1 - phishing_proba) * 100:.2f}%)"

st.title("Real-Time Phishing detector.")
st.write("Enter any URL to check"," ")

url = st.text_input("URL HERE!!")

if st.button("Verify"):

      if url:
          result=predict_url(url)
          st.write(result)
      else:
          st.write("Enter valid URL")
    