import re
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import json
import logging
import pandas as pd
import tensorflow as tf
import traceback

# Logging setup
logging.basicConfig(filename='sql_injection.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# SQL injection patterns
INJECTION_PATTERNS = [
    r'\b(union|select|drop|alter|create|delete|update|insert)\b.*\b(from|into|table)\b',
    r'(--|\#|\/\*|\*\/)',
    r'\b(exec|execute|sp_\w+)\b',
    r'(;|\'|\bOR\b\s*[\'"]?1[\'"]?=[\'"]?1)',
    r'(\bAND\b\s*[\'"]?1[\'"]?=[\'"]?1)',
    r'(\|\||&&)',
    r'(\bWAITFOR\b|\bDELAY\b)',
]

# Email configuration
ADMIN_EMAIL = 'your_admin@example.com'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USER = 'your_email@gmail.com'
SMTP_PASS = 'your_app_password'

# Files
ALERTS_FILE = 'alerts.json'
LOGIN_ATTEMPTS_FILE = 'login_attempts.json'

def preprocess_query(query, tokenizer, maxlen=100):
    """Preprocess query for LSTM-based SQLi detection."""
    try:
        if not query:
            return tf.keras.preprocessing.sequence.pad_sequences([[0]], maxlen=maxlen)
        sequences = tokenizer.texts_to_sequences([query.lower()])
        padded = tf.keras.preprocessing.sequence.pad_sequences(sequences, maxlen=maxlen)
        return padded
    except Exception as e:
        logging.error(f'Error in preprocess_query: {str(e)}\n{traceback.format_exc()}')
        raise

def is_injection(query):
    """Detect SQL injection using regex patterns."""
    if not query:
        return False
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, query.lower(), re.IGNORECASE):
            logging.info(f'SQL injection pattern detected: {query}')
            return True
    return False

def notify_admin(message, ip_address, block_ip=False):
    """Log and notify admin of suspicious activity."""
    alert = {
        'timestamp': datetime.utcnow().isoformat(),
        'message': message,
        'ip_address': ip_address,
        'blocked': block_ip
    }
    try:
        try:
            with open(ALERTS_FILE, 'r') as f:
                alerts = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            alerts = []
        alerts.append(alert)
        with open(ALERTS_FILE, 'w') as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        logging.error(f'Failed to save alert: {e}\n{traceback.format_exc()}')

    # Email notification (optional)
    try:
        msg = MIMEText(f'Security Alert:\n\n{message}\nIP: {ip_address}\nBlocked: {block_ip}')
        msg['Subject'] = 'SmartGuard Security Alert'
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        logging.error(f'Failed to send email: {e}\n{traceback.format_exc()}')

def get_blocked_ips():
    """Retrieve list of blocked IPs."""
    try:
        with open(ALERTS_FILE, 'r') as f:
            alerts = json.load(f)
        return {alert['ip_address'] for alert in alerts if alert.get('blocked', False)}
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def log_login_attempt(username, ip_address, success, reason):
    """Log login attempts."""
    attempt = {
        'timestamp': datetime.utcnow().isoformat(),
        'username': username,
        'ip_address': ip_address,
        'success': success,
        'reason': reason
    }
    try:
        try:
            with open(LOGIN_ATTEMPTS_FILE, 'r') as f:
                attempts = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            attempts = []
        attempts.append(attempt)
        with open(LOGIN_ATTEMPTS_FILE, 'w') as f:
            json.dump(attempts, f, indent=2)
    except Exception as e:
        logging.error(f'Failed to log login attempt: {e}\n{traceback.format_exc()}')

def calculate_entropy(text):
    """Calculate Shannon entropy of a string for phishing detection."""
    if not text:
        return 0.0
    length = len(text)
    if length <= 1:
        return 0.0
    prob = [float(text.count(c)) / length for c in set(text)]
    return -sum(p * np.log2(p) for p in prob if p > 0)

def extract_url_features(url, feature_names):
    """Extract features from a URL for phishing detection."""
    try:
        url = url.rstrip('/').lower()
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        fragment = parsed_url.fragment
        features = {name: 0 for name in feature_names}
        
        # Populate features
        features['url_length'] = len(url)
        features['number_of_dots_in_url'] = url.count('.')
        features['having_repeated_digits_in_url'] = 1 if re.search(r'(\d)\1', url) else 0
        features['number_of_digits_in_url'] = sum(c.isdigit() for c in url)
        features['number_of_special_char_in_url'] = sum(not c.isalnum() and c != '.' for c in url)
        features['number_of_hyphens_in_url'] = url.count('-')
        features['number_of_underline_in_url'] = url.count('_')
        features['number_of_slash_in_url'] = url.count('/')
        features['number_of_questionmark_in_url'] = url.count('?')
        features['number_of_equal_in_url'] = url.count('=')
        features['number_of_at_in_url'] = url.count('@')
        features['number_of_dollar_in_url'] = url.count('$')
        features['number_of_exclamation_in_url'] = url.count('!')
        features['number_of_hashtag_in_url'] = url.count('#')
        features['number_of_percent_in_url'] = url.count('%')
        features['domain_length'] = len(domain)
        features['number_of_dots_in_domain'] = domain.count('.')
        features['number_of_hyphens_in_domain'] = domain.count('-')
        features['having_special_characters_in_domain'] = 1 if any(not c.isalnum() and c != '.' and c != '-' for c in domain) else 0
        features['number_of_special_characters_in_domain'] = sum(not c.isalnum() and c != '.' and c != '-' for c in domain)
        features['having_digits_in_domain'] = 1 if any(c.isdigit() for c in domain) else 0
        features['number_of_digits_in_domain'] = sum(c.isdigit() for c in domain)
        features['having_repeated_digits_in_domain'] = 1 if re.search(r'(\d)\1', domain) else 0
        subdomains = domain.split('.')[:-2]
        features['number_of_subdomains'] = len(subdomains)
        features['having_dot_in_subdomain'] = 1 if any('.' in subd for subd in subdomains) else 0
        features['having_hyphen_in_subdomain'] = 1 if any('-' in subd for subd in subdomains) else 0
        features['average_subdomain_length'] = np.mean([len(subd) for subd in subdomains]) if subdomains else 0
        features['average_number_of_dots_in_subdomain'] = np.mean([subd.count('.') for subd in subdomains]) if subdomains else 0
        features['average_number_of_hyphens_in_subdomain'] = np.mean([subd.count('-') for subd in subdomains]) if subdomains else 0
        features['having_special_characters_in_subdomain'] = 1 if any(not c.isalnum() and c != '.' and c != '-' for subd in subdomains for c in subd) else 0
        features['number_of_special_characters_in_subdomain'] = sum(not c.isalnum() and c != '.' and c != '-' for subd in subdomains for c in subd)
        features['having_digits_in_subdomain'] = 1 if any(c.isdigit() for subd in subdomains for c in subd) else 0
        features['number_of_digits_in_subdomain'] = sum(c.isdigit() for subd in subdomains for c in subd)
        features['having_repeated_digits_in_subdomain'] = 1 if any(re.search(r'(\d)\1', subd) for subd in subdomains) else 0
        features['having_path'] = 1 if path else 0
        features['path_length'] = len(path)
        features['having_query'] = 1 if query else 0
        features['having_fragment'] = 1 if fragment else 0
        features['having_anchor'] = 1 if '#' in url else 0
        features['entropy_of_url'] = calculate_entropy(url)
        features['entropy_of_domain'] = calculate_entropy(domain)
        
        logging.debug(f'Extracted features for {url}: {features}')
        return features
    except Exception as e:
        logging.error(f'Error extracting features for URL {url}: {str(e)}\n{traceback.format_exc()}')
        return {name: 0 for name in feature_names}

def test_url_phishing(url, model, scaler, feature_names):
    """Test a URL for phishing using the Random Forest model."""
    logging.debug(f'Testing URL for phishing: {url}')
    try:
        if not url or not isinstance(url, str):
            logging.error(f'Invalid URL: {url}')
            return {'is_phishing': False, 'phishing_probability': 0.0}
        
        features = extract_url_features(url, feature_names)
        
        # Ensure feature alignment
        feature_dict = {name: features.get(name, 0) for name in feature_names}
        feature_values = [feature_dict[name] for name in feature_names]
        logging.debug(f'Feature values for model: {feature_values}')
        
        # Convert to DataFrame for scaling
        feature_df = pd.DataFrame([feature_values], columns=feature_names)
        features_scaled = scaler.transform(feature_df)
        
        # Predict
        prediction = model.predict(features_scaled)[0]
        probability = model.predict_proba(features_scaled)[0][1]
        
        logging.debug(f'Phishing prediction: is_phishing={prediction}, probability={probability}')
        return {
            'is_phishing': bool(prediction),
            'phishing_probability': float(probability)
        }
    except Exception as e:
        logging.error(f'Error in test_url_phishing for {url}: {str(e)}\n{traceback.format_exc()}')
        return {
            'is_phishing': False,
            'phishing_probability': 0.0
        }