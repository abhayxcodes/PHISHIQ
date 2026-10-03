# 🛡️ PhishIQ — Phishing Management System

> Detect phishing in URLs, emails, and SMS. Understand *why* it was flagged. Know what to do if you've already been hit.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20App-black)
![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange)
![Docker](https://img.shields.io/badge/Docker-supported-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)

PhishIQ is a Flask web app that combines **rule-based detection** with **machine learning models** to catch phishing across three channels: **URLs, emails, and SMS**. If something goes wrong, a built-in **Recovery Center** walks you through the next steps.

---

## Table of Contents

- [Why PhishIQ?](#why-phishiq)
- [Features](#features)
- [How It Works](#how-it-works)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Run with Docker](#run-with-docker)
- [Training the Models](#training-the-models)
- [Usage](#usage)
- [Risk Scoring](#risk-scoring)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

---

## Why PhishIQ?

Most phishing checkers give you a yes/no and nothing else. PhishIQ is built around three ideas:

1. **Explain, don't just flag.** Every scan returns human-readable reasons (e.g. "@ symbol detected", "short link found").
2. **Two opinions are better than one.** A transparent rule engine and an ML model score every input independently.
3. **Detection isn't the end.** If you clicked the link or shared an OTP, you need a plan, not just a warning.

---

## Features

| Module | What it does |
|---|---|
| 🔗 **URL Scanner** | Analyzes a link using 51 engineered features plus heuristic rules (IP addresses, `@` tricks, hyphenated domains, subdomain depth, suspicious keywords, and more). |
| 📧 **Email Scanner** | Scans email text for suspicious, urgent, and sensitive-info keywords, bad TLDs (`.xyz`, `.top`, `.tk`, `.gq`), link stacking, and grammar errors. |
| 💬 **SMS Scanner** | Detects smishing using TF-IDF + Random Forest, plus checks for short links, urgency language, fake-login patterns, and digit-heavy or all-caps messages. |
| 🖼️ **Screenshot OCR** | Upload a screenshot of an email or SMS. Text is extracted with Tesseract and scanned automatically. |
| 📊 **Risk Dashboard** | Shows a risk percentage, a Low / Medium / High verdict, the ML probability, and every reason behind the score. |
| 🚑 **Recovery Center** | Step-by-step guidance for compromised passwords, bank details, leaked OTPs, and infected devices. Includes India's Cyber Crime Helpline (**1930**). |

---

## How It Works

```
              ┌──────────────┐
   Input      │ URL / Email  │   (email & SMS also accept screenshots → Tesseract OCR)
              │ / SMS        │
              └──────┬───────┘
                     │
            ┌────────┴────────┐
            ▼                 ▼
     ┌─────────────┐   ┌───────────────┐
     │ Rule Engine │   │ ML Model      │
     │ keyword &   │   │ Random Forest │
     │ pattern     │   │ + features /  │
     │ scoring     │   │ TF-IDF        │
     └──────┬──────┘   └───────┬───────┘
            └────────┬─────────┘
                     ▼
             ┌───────────────┐
             │  Dashboard    │  risk %, verdict, ML probability, reasons
             └───────┬───────┘
                     ▼
             ┌───────────────┐
             │ Recovery      │  what to do if you've been hit
             └───────────────┘
```

**Rule engine:** Each red flag adds 10 points (30 for heavy grammar errors in emails). The total is normalized to a 0–100% risk score.

**ML layer:** Each channel has its own Random Forest classifier, trained on public datasets:

| Channel | Dataset | Model | Input |
|---|---|---|---|
| URL | PhiUSIIL Phishing URL Dataset | Random Forest (600 trees, balanced) | 51 handcrafted URL features |
| Email | CEAS-08 | Random Forest (200 trees, depth 20) | TF-IDF (50 terms) + URL feature |
| SMS | Dataset_10191 (ham / spam / smishing) | Random Forest (200 trees, depth 25) | TF-IDF (3000 terms, 1–2 grams) |

---

## Tech Stack

- **Backend:** Python, Flask
- **ML:** scikit-learn (RandomForest, TF-IDF), pandas, NumPy, SciPy, joblib
- **NLP / text:** LanguageTool (`language_tool_python`), pytesseract, Pillow
- **URL parsing:** `tldextract`, `urllib`
- **Frontend:** Jinja2 templates (HTML/CSS)
- **Deployment:** Docker

---

## Project Structure

```
PHISHIQ/
├── app.py                  # Flask app: routes, scoring, model loading
├── Machine_learning/       # Feature extraction, training scripts, trained .pkl models
├── abhay_csv/              # CSV data used by the project
├── templates/              # Jinja2 templates (home, url, email, sms, dashboard, recovery)
├── Dockerfile              # Container build
├── requirements.txt        # Python dependencies
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.9+
- Java 8+ (required by LanguageTool)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) installed and on your `PATH`

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/abhayxcodes/PHISHIQ.git
cd PHISHIQ

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Check model paths

Make sure `app.py` loads the trained models using paths that exist on your machine. Relative paths are the most portable:

```python
import os, joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE_DIR, "Machine_learning", "phishing_model.pkl"))
```

### Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## Run with Docker

```bash
docker build -t phishiq .
docker run -p 5000:5000 phishiq
```

Then open **http://localhost:5000**. If your `Dockerfile` exposes a different port, adjust the `-p` mapping to match.

---

## Training the Models

Download the datasets, update the CSV paths at the top of each training script, then run:

```bash
python Machine_learning/url_ml_model.py     # URL model
python Machine_learning/email_ml_model.py   # Email model + TF-IDF vectorizer
python Machine_learning/sms_ml_model.py     # SMS model + TF-IDF vectorizer
```

> ⚠️ Make sure each script saves to a **different filename** so the URL and SMS models don't overwrite each other.

**Datasets**

- [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (URLs)
- CEAS-08 (emails)
- SMS phishing dataset with `ham`, `spam`, and `smishing` labels (SMS)

---

## Usage

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Landing page |
| `/url` | GET, POST | Scan a URL |
| `/email` | GET, POST | Scan email text or a screenshot |
| `/sms` | GET, POST | Scan SMS text or a screenshot |
| `/recovery` | GET, POST | Get recovery steps (`password`, `bank`, `otp`, `device`) |

**Example:** Open `/sms`, paste a suspicious message such as *"Your account is suspended. Verify now: bit.ly/xyz"*, and hit **Scan**. The dashboard flags the keywords, the short link, and the urgency wording, then shows the ML probability next to the rule-based risk score.

---

## Risk Scoring

| Risk % | Verdict |
|---|---|
| Below 30% | ✅ Low Risk |
| 30% – 59% | ⚠️ Medium Risk |
| 60% and above | 🚨 High Risk |

The risk percentage comes from the rule engine. The ML probability is shown alongside it as a second opinion.

---

## Known Limitations

- **Not a replacement for enterprise security tools.** It's a decision-support tool for individuals and learning projects.
- **Keyword rules are simple.** Substring matching can produce false positives.
- **Trusted-domain allowlist is small.** Only a handful of major domains bypass URL scoring.
- **English-centric.** Grammar checking and TF-IDF vocabularies are English only.
- **Model files must match the feature pipeline.** If you change the feature extraction code, retrain the models.
- **Accuracy depends on the training data.** Add your benchmark results below.

| Model | Accuracy | Precision | Recall |
|---|---|---|---|
| URL | _TBD_ | _TBD_ | _TBD_ |
| Email | _TBD_ | _TBD_ | _TBD_ |
| SMS | _TBD_ | _TBD_ | _TBD_ |

---

## Roadmap

- [x] `requirements.txt`
- [x] Docker support
- [ ] Combine rule score and ML probability into one final verdict
- [ ] Multilingual support (Hindi and regional languages)
- [ ] Live URL reputation checks (Google Safe Browsing, VirusTotal)
- [ ] Scan history and reporting dashboard
- [ ] Browser extension
- [ ] Cloud deployment
- [ ] Unit tests for feature extraction

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push and open a Pull Request

---

## Author

**Abhay** — [@abhayxcodes](https://github.com/abhayxcodes)

Built as a phishing awareness and management project.

---

## License

Released under the MIT License. Add a `LICENSE` file to the repo root to make this official.

---

**Stay sharp. Think before you click. 🛡️**
