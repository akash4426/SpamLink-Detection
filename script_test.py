import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver
import pandas as pd

# Load trained model and feature order
model = joblib.load("phishing_model_updated.pkl")
with open("model_features.txt", "r") as f:
    expected_columns = f.read().splitlines()

# DNS cache
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

# Trusted domains and suspicious hosts
trusted_domains = ["paypal.com", "google.com", "microsoft.com", "apple.com"]
suspicious_hosts = ["trycloudflare.com", "glitch.me", "replit.dev", "web.app"]

# Prediction function
def predict_url(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain_parts = ext.subdomain.split('.')

    # Whitelisted domains shortcut
    if any(t in domain for t in trusted_domains):
        return "✅ Legitimate (Whitelisted)"

    # Suspicious hosting detection
    if domain in suspicious_hosts and len(subdomain_parts) >= 2:
        return f"🚨 Phishing (Suspicious subdomain on {domain})"

    # Extract features
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

    # Build input dataframe and align columns
    input_df = pd.DataFrame([features])
    input_df = input_df.reindex(columns=expected_columns)

    # Convert to numpy array to avoid feature name warnings
    input_df_np = input_df.values

    # Prediction
    phishing_proba = model.predict_proba(input_df_np)[0][1]

    if phishing_proba > 0.6:
        return "🚨 Phishing"
    elif phishing_proba > 0.4:
        return "⚠️ Suspicious"
    else:
        return "✅ Legitimate"

# 🔄 Main CLI loop
if __name__ == "__main__":
    while True:
        url = input("\n🔗 Enter a URL to test (or type 'exit' to quit):\n> ")
        if url.lower() == "exit":
            print("👋 Exiting the detector. Stay safe!")
            break
        result = predict_url(url)
        print(f"\n🔍 Result: {result}")
