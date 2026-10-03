# 🛡️ PhishIQ — Phishing Detection System

> An ML-powered cybersecurity web application for detecting potentially malicious URLs, emails, and SMS messages.

PhishIQ is a machine-learning-based phishing detection system built with **Python and Flask**. It analyzes suspicious URLs, email content, and SMS messages using trained machine-learning models and presents the results through a simple web interface.

The project was developed as a practical cybersecurity project to explore the application of **machine learning, web development, threat detection, and secure software deployment**.

---

## 🚀 Features

### 🔗 URL Phishing Detection

Analyze a URL and classify it using a trained machine-learning model.

The system uses URL-related features to identify patterns commonly associated with phishing URLs.

### 📧 Email Phishing Detection

Analyze email content and identify characteristics that may indicate a phishing attempt.

### 📱 SMS Phishing Detection

Analyze suspicious SMS messages and classify them using a dedicated machine-learning model.

### 📊 Risk Analysis

PhishIQ presents detection results in a user-friendly format so that users can better understand the potential risk associated with submitted content.

### 🔐 Recovery Assistance

The application provides basic guidance for users who believe they may have interacted with a suspicious URL, email, or SMS.

### 🧪 Automated Testing

The project includes tests for important application functionality using Pytest.

---

# 🧠 How It Works

PhishIQ follows a simple detection pipeline:

```text
                    User Input
                        │
          ┌─────────────┼─────────────┐
          │             │             │
         URL          Email          SMS
          │             │             │
          ▼             ▼             ▼
   Feature Extraction / Text Processing
          │             │             │
          └─────────────┼─────────────┘
                        ▼
              Machine Learning Model
                        │
                        ▼
                 Risk Classification
                        │
                        ▼
                User-Friendly Result
The application receives the user's input, processes the relevant features, sends them to the appropriate trained model, and displays the resulting classification through the Flask web interface.

🏗️ Project Structure
PHISHIQ/
│
├── app.py
├── requirements.txt
├── Dockerfile
├── README.md
├── .gitignore
├── .gitattributes
│
├── datasets/
│   ├── CEAS_08.csv
│   ├── Dataset_10191.csv
│   └── PhiUSIIL_Phishing_URL_Dataset.csv
│
├── models/
│   ├── url_model.pkl
│   ├── email_model.pkl
│   ├── sms_model.pkl
│   ├── sms_threshold.json
│   ├── url_features.npy
│   └── url_features_meta.json
│
├── ml_models/
│   └── ...
│
├── templates/
│   ├── home.html
│   ├── url.html
│   ├── email.html
│   ├── sms.html
│   ├── dashboard.html
│   └── recovery.html
│
└── tests/
    └── ...
🛠️ Technology Stack
Backend
Python
Flask
Gunicorn
Machine Learning
Scikit-learn
NumPy
Pandas
Joblib
Frontend
HTML
CSS
JavaScript
Jinja2
Testing
Pytest
Deployment & Development
Git
GitHub
Git LFS
Docker
Render
🤖 Machine Learning Models

PhishIQ uses dedicated trained models for different types of input.

Detection	Model
URL	url_model.pkl
Email	email_model.pkl
SMS	sms_model.pkl

Additional supporting files are used for feature processing and prediction configuration.

models/
├── url_model.pkl
├── url_features.npy
├── url_features_meta.json
├── email_model.pkl
├── sms_model.pkl
└── sms_threshold.json

Large machine-learning models and datasets are managed using Git LFS.

📂 Datasets

The project contains datasets used for machine-learning development.

Current datasets include:

CEAS 08
Dataset 10191
PhiUSIIL Phishing URL Dataset

The use and redistribution of third-party datasets should follow their respective licenses and terms.

💻 Local Installation
1. Clone the Repository
git clone https://github.com/abhayxcodes/PHISHIQ-Phishing-Detection-System.git

Navigate to the project:

cd PHISHIQ-Phishing-Detection-System
2. Create a Virtual Environment
Windows
python -m venv venv

Activate it:

venv\Scripts\activate
Linux / macOS
python3 -m venv venv

Activate it:

source venv/bin/activate
3. Install Dependencies
pip install -r requirements.txt
4. Run the Application
python app.py

The application will normally be available at:

http://127.0.0.1:5000
🧪 Testing

Run the test suite:

pytest

For detailed output:

pytest -v
🐳 Docker

PhishIQ includes a Docker configuration for containerized deployment.

Build the Image
docker build -t phishiq .
Run the Container
docker run -p 5000:5000 phishiq

Open:

http://localhost:5000

The application is served using Gunicorn inside the container.

🌐 Render Deployment

PhishIQ is designed to be deployable as a Docker-based web service on Render.

Deployment Configuration
Repository:
PHISHIQ-Phishing-Detection-System

Branch:
main

Runtime:
Docker

The included Dockerfile handles the application environment and starts the Flask application using Gunicorn.

Production startup command:

gunicorn --bind 0.0.0.0:5000 app:app
Environment Variables

Production secrets should not be committed to GitHub.

Configure them through the deployment platform.

Example:

SECRET_KEY=<your-secret-key>
FLASK_DEBUG=false
📦 Git LFS

PhishIQ contains large machine-learning models and datasets.

Git LFS is used to manage these files.

Install Git LFS:

git lfs install

Check LFS-tracked files:

git lfs ls-files

The repository uses Git LFS for large files such as:

*.pkl
*.csv
*.npy
*.json
🔒 Security & Privacy

PhishIQ is a defensive cybersecurity and educational project.

Machine-learning predictions are not guaranteed to be correct and may result in false positives or false negatives.

Do not submit real passwords, OTPs, banking credentials, API keys, or other sensitive information while testing the application.

🎯 Project Objectives

The project was developed to demonstrate practical implementation of:

Machine learning in cybersecurity
Phishing detection
Flask web application development
Machine-learning model integration
Data processing
Security-focused UI development
Automated testing
Docker containerization
Cloud deployment
🔮 Future Improvements

Potential future improvements include:

Real-time threat intelligence integration
Domain reputation analysis
WHOIS and DNS analysis
URL shortening detection
Improved ML explainability
Additional phishing datasets
Model performance monitoring
Security event logging
API endpoints
User authentication and scan history
👨‍💻 Developer
Abhay Soni

B.Tech CSE Student
Cybersecurity / Defensive Security Enthusiast

GitHub:
https://github.com/abhayxcodes

⚠️ Disclaimer

PhishIQ is a student and educational cybersecurity project developed for learning, research, and defensive security purposes.

The system's prediction should not be considered definitive proof that a URL, email, or SMS is safe or malicious.

Always verify suspicious communications through trusted sources and follow appropriate cybersecurity practices.

⭐ Project

If you find the project useful, feel free to explore the implementation and suggest improvements.
