from flask import Flask, render_template, request
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import re
import tldextract
from sklearn.metrics import accuracy_score
import joblib
import os

app = Flask(__name__, template_folder='../frontend', static_folder='../frontend/static')

# Sample data for training
emails = [
    "Dear user, your account has been compromised. Please reset your password immediately.",
    "Urgent! Your bank account is at risk. Please click this link to confirm your identity.",
    "Hello, your Amazon order has been shipped. Track it here.",
    "Thank you for your recent purchase! Your receipt is attached.",
    # More examples should be added here
]

labels = ['phishing', 'phishing', 'legitimate', 'legitimate']

# Expanded keywords and trusted domains
phishing_keywords = ["urgent", "compromised", "verify", "password", "account", "identity", "click", "risk"]
trusted_domains = ["amazon.com", "paypal.com", "google.com", "microsoft.com", "netflix.com", "ebay.com", "yahoo.com"]

# Vectorizer and model setup
vectorizer = TfidfVectorizer(stop_words='english', ngram_range=(1, 2))  # Using TF-IDF with unigrams and bigrams
X = vectorizer.fit_transform(emails)
y = labels

# Train the model
model = MultinomialNB()
model.fit(X, y)

# Save the trained model and vectorizer (optional)
if not os.path.exists('model'):
    os.makedirs('model')
joblib.dump(model, 'model/phishing_model.pkl')
joblib.dump(vectorizer, 'model/vectorizer.pkl')

# Helper functions
def extract_domain_from_email(email):
    """Extract domain from email URL."""
    urls = re.findall(r"https?://[^\s]+", email)
    return [tldextract.extract(url).registered_domain for url in urls]

def is_phishing_domain(domains):
    """Check if the email has untrusted domains."""
    return any(domain not in trusted_domains for domain in domains)

def detect_phishing(email):
    """Detect phishing and return result."""
    email_vector = vectorizer.transform([email])
    prediction = model.predict(email_vector)[0]
    domains = extract_domain_from_email(email)
    
    # Check if there are untrusted domains
    if is_phishing_domain(domains):
        return "phishing (untrusted domain)"
    
    return prediction

def highlight_phishing_keywords(email):
    """Highlight phishing keywords and untrusted domains."""
    highlighted_email = email
    matched_keywords = []
    
    # Highlight phishing keywords
    for keyword in phishing_keywords:
        if re.search(rf"\b{keyword}\b", email, re.IGNORECASE):
            matched_keywords.append(keyword)
            highlighted_email = re.sub(
                rf"\b({keyword})\b",
                r"<span style='color:red; font-weight:bold;'>\1</span>",
                highlighted_email,
                flags=re.IGNORECASE
            )
    
    # Highlight untrusted domains
    domains = extract_domain_from_email(email)
    for domain in domains:
        if domain not in trusted_domains:
            highlighted_email = re.sub(
                re.escape(domain),
                f"<span style='color:orange; font-weight:bold;'>{domain} (untrusted)</span>",
                highlighted_email
            )
    
    # Return the matched phishing keywords for explanation
    return highlighted_email, matched_keywords

@app.route('/')
def home():
    """Home page."""
    return render_template('defense.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    """Phishing prediction endpoint."""
    if request.method == 'POST':
        email = request.form.get('email', '')  # Get email input
        
        if email.strip():
            # Predict phishing status
            prediction = detect_phishing(email)
            
            # Highlight phishing keywords and untrusted domains
            highlighted_email, matched_keywords = highlight_phishing_keywords(email)
            
            # Provide a reason for phishing detection
            reason = ""
            if prediction == "phishing":
                reason = f"Phishing due to the following indicators: {', '.join(matched_keywords)}"
            else:
                reason = "No phishing indicators found."
            
            return render_template('defense.html', prediction=prediction, email=highlighted_email, reason=reason)
        
        return render_template('defense.html', prediction="No input provided", email=email)
    
    return render_template('defense.html')

if __name__ == '__main__':
    app.run(debug=True, port=2001)
