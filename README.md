\# 🛡️ PhishIQ — Phishing Management System



PhishIQ is a Flask web app that combines \*\*rule-based detection\*\* with \*\*machine learning models\*\* to catch phishing across three channels: URLs, emails, and SMS. If something goes wrong, a built-in \*\*Recovery Center\*\* walks you through the next steps.



\---



\## Table of Contents



\- \[Why PhishIQ?](#why-phishiq)

\- \[Features](#features)

\- \[How It Works](#how-it-works)

\- \[Tech Stack](#tech-stack)

\- \[Project Structure](#project-structure)

\- \[Getting Started](#getting-started)

\- \[Training the Models](#training-the-models)

\- \[Usage](#usage)

\- \[Risk Scoring](#risk-scoring)

\- \[Known Limitations](#known-limitations)

\- \[Roadmap](#roadmap)

\- \[Contributing](#contributing)

\- \[Author](#author)



\---



\## Why PhishIQ?



Most phishing checkers give you a yes/no and nothing else. PhishIQ is built around three ideas:



1\. \*\*Explain, don't just flag.\*\* Every scan returns a list of human-readable reasons (e.g. "@ symbol detected", "short link found").

2\. \*\*Two opinions are better than one.\*\* A transparent rule engine and an ML model score every input independently.

3\. \*\*Detection isn't the end.\*\* If you clicked the link or shared an OTP, you need a plan, not just a warning.



\---



\## Features



| Module | What it does |

|---|---|

| 🔗 \*\*URL Scanner\*\* | Analyzes a link using 51 engineered features + heuristic rules (IP addresses, `@` tricks, hyphenated domains, subdomain depth, suspicious keywords, and more). |

| 📧 \*\*Email Scanner\*\* | Scans email text for suspicious, urgent, and sensitive-info keywords, bad TLDs (`.xyz`, `.top`, `.tk`, `.gq`), link stacking, and grammar errors. |

| 💬 \*\*SMS Scanner\*\* | Detects smishing using TF-IDF + Random Forest, plus checks for short links, urgency language, fake-login patterns, and digit-heavy or all-caps messages. |

| 🖼️ \*\*Screenshot OCR\*\* | Upload a screenshot of an email or SMS. Text is extracted with Tesseract and scanned automatically. |

| 📊 \*\*Risk Dashboard\*\* | Shows a risk percentage, a Low / Medium / High verdict, the ML probability, and every reason behind the score. |

| 🚑 \*\*Recovery Center\*\* | Step-by-step guidance for compromised passwords, bank details, leaked OTPs, and infected devices. Includes India's Cyber Crime Helpline (\*\*1930\*\*). |



\---



\## How It Works



```

\&#x20;       ┌──────────────┐

\&#x20;Input  │ URL / Email  │   (email \\\& SMS also accept screenshots → Tesseract OCR)

\&#x20;       │ / SMS        │

\&#x20;       └──────┬───────┘

\&#x20;              │

\&#x20;      ┌───────┴────────┐

\&#x20;      ▼                ▼

┌─────────────┐  ┌───────────────┐

│ Rule Engine │  │ ML Model      │

│ keyword \\\&   │  │ Random Forest │

│ pattern     │  │ + features /  │

│ scoring     │  │ TF-IDF        │

└──────┬──────┘  └───────┬───────┘

\&#x20;      └────────┬────────┘

\&#x20;               ▼

\&#x20;       ┌───────────────┐

\&#x20;       │  Dashboard    │  risk %, verdict, ML probability, reasons

\&#x20;       └───────┬───────┘

\&#x20;               ▼

\&#x20;       ┌───────────────┐

\&#x20;       │ Recovery      │  what to do if you've been hit

\&#x20;       └───────────────┘

```



\*\*Rule engine:\*\* Each red flag adds 10 points (30 for heavy grammar errors in emails). The total is normalized to a 0–100% risk score.



\*\*ML layer:\*\* Each channel has its own Random Forest classifier, trained on public datasets:



| Channel | Dataset | Model | Input |

|---|---|---|---|

| URL | PhiUSIIL Phishing URL Dataset | Random Forest (600 trees, balanced) | 51 handcrafted URL features |

| Email | CEAS-08 | Random Forest (200 trees, depth 20) | TF-IDF (50 terms) + URL feature |

| SMS | Dataset\_10191 (ham / spam / smishing) | Random Forest (200 trees, depth 25) | TF-IDF (3000 terms, 1–2 grams) |



\---



\## Tech Stack



\- \*\*Backend:\*\* Python, Flask

\- \*\*ML:\*\* scikit-learn (RandomForest, TF-IDF), pandas, NumPy, SciPy, joblib

\- \*\*NLP / text:\*\* LanguageTool (`language\\\_tool\\\_python`), pytesseract, Pillow

\- \*\*URL parsing:\*\* `tldextract`, `urllib`

\- \*\*Frontend:\*\* Jinja2 templates (HTML/CSS)



\---



\## Project Structure



```

project\\\_phishiq/

├── app.py                      # Flask app: routes, scoring, model loading

├── Machine\\\_learning/

│   ├── Features.py             # URL, email, and SMS feature extraction

│   ├── url\\\_ml\\\_model.py         # Train URL model

│   ├── email\\\_ml\\\_model.py       # Train email model

│   ├── sms\\\_ml\\\_model.py         # Train SMS model

│   ├── phishing\\\_model.pkl      # Trained URL model

│   ├── email\\\_rf\\\_model.pkl      # Trained email model

│   ├── email\\\_tfidf.pkl         # Email TF-IDF vectorizer

│   ├── sms\\\_rf\\\_model.pkl        # Trained SMS model

│   └── sms\\\_vectorizer.pkl      # SMS TF-IDF vectorizer

├── templates/

│   ├── home.html

│   ├── url.html

│   ├── email.html

│   ├── sms.html

│   ├── dashboard.html

│   └── recovery.html

└── README.md

```



\---



\## Getting Started



\### Prerequisites



\- Python 3.9+

\- Java 8+ (required by LanguageTool)

\- \[Tesseract OCR](https://github.com/tesseract-ocr/tesseract) installed and on your `PATH`



\### Installation



```bash

\\# 1. Clone the repo

git clone https://github.com/<your-username>/phishiq.git

cd phishiq



\\# 2. Create a virtual environment

python -m venv venv

source venv/bin/activate        # Windows: venv\\\\Scripts\\\\activate



\\# 3. Install dependencies

pip install flask pandas numpy scipy scikit-learn joblib \\\\

\&#x20;           tldextract language-tool-python pytesseract pillow

```



\### Configure model paths



`app.py` currently loads models from absolute Windows paths. Update them to match your machine, or switch to relative paths:



```python

BASE\\\_DIR = os.path.dirname(os.path.abspath(\\\_\\\_file\\\_\\\_))

model = joblib.load(os.path.join(BASE\\\_DIR, "Machine\\\_learning", "phishing\\\_model.pkl"))

```



\### Run



```bash

python app.py

```



Open \*\*http://127.0.0.1:5000\*\* in your browser.



\---



\## Training the Models



Download the datasets, update the CSV paths at the top of each script, then run:



```bash

python Machine\\\_learning/url\\\_ml\\\_model.py     # → phishing\\\_model.pkl

python Machine\\\_learning/email\\\_ml\\\_model.py   # → email\\\_rf\\\_model.pkl, email\\\_tfidf.pkl

python Machine\\\_learning/sms\\\_ml\\\_model.py     # → phishing\\\_model.pkl, vectorizer.pkl

```



> ⚠️ The URL and SMS scripts both save a file named `phishing\\\_model.pkl`. Rename one of the outputs (for example `sms\\\_rf\\\_model.pkl` for SMS) so they don't overwrite each other.



\*\*Datasets\*\*



\- \[PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (URLs)

\- CEAS-08 (emails)

\- SMS phishing dataset with `ham`, `spam`, and `smishing` labels (SMS)



\---



\## Usage



| Route | Method | Purpose |

|---|---|---|

| `/` | GET | Landing page |

| `/url` | GET, POST | Scan a URL |

| `/email` | GET, POST | Scan email text or a screenshot |

| `/sms` | GET, POST | Scan SMS text or a screenshot |

| `/recovery` | GET, POST | Get recovery steps (`password`, `bank`, `otp`, `device`) |



\*\*Example flow:\*\* Open `/sms`, paste a suspicious message like \*"Your account is suspended. Verify now: bit.ly/xyz"\*, and hit Scan. The dashboard flags the keywords, the short link, and the urgency wording, then shows the ML probability alongside the rule-based risk score.



\---



\## Risk Scoring



| Risk % | Verdict |

|---|---|

| Below 30% | ✅ Low Risk |

| 30% – 59% | ⚠️ Medium Risk |

| 60% and above | 🚨 High Risk |



(The URL scanner treats 30% exactly as Low and 60% exactly as Medium.)



The risk percentage comes from the rule engine. The ML probability is displayed next to it as a second opinion.



\---



\## Known Limitations



Being upfront about where this project stands:



\- \*\*Not a replacement for enterprise security tools.\*\* It's a decision-support tool for individuals and learning projects.

\- \*\*Keyword rules are simple.\*\* Substring matching can produce false positives (for example "now" appearing inside another word).

\- \*\*Trusted-domain allowlist is small.\*\* Only a handful of major domains bypass URL scoring.

\- \*\*English-centric.\*\* Grammar checking and TF-IDF vocabularies are English only.

\- \*\*Model files must match the feature pipeline.\*\* If you change `Features.py`, retrain the models.

\- \*\*Accuracy depends on the training data.\*\* Add your own evaluation results below once you've benchmarked the models.



| Model | Accuracy | Precision | Recall |

|---|---|---|---|

| URL | \_TBD\_ | \_TBD\_ | \_TBD\_ |

| Email | \_TBD\_ | \_TBD\_ | \_TBD\_ |

| SMS | \_TBD\_ | \_TBD\_ | \_TBD\_ |



\---



\## Roadmap



\- \[ ] Relative paths + a `requirements.txt` and `.env` config

\- \[ ] Combine rule score and ML probability into one final verdict

\- \[ ] Multilingual support (Hindi and regional languages)

\- \[ ] Live URL reputation checks (Google Safe Browsing, VirusTotal)

\- \[ ] Scan history and reporting dashboard

\- \[ ] Browser extension

\- \[ ] Docker image and cloud deployment

\- \[ ] Unit tests for feature extraction



\---



\## Contributing



Contributions are welcome.



1\. Fork the repository

2\. Create a branch: `git checkout -b feature/your-feature`

3\. Commit your changes: `git commit -m "Add your feature"`

4\. Push and open a Pull Request



\---



\## Author



\*\*Abhay\*\*

Built as a phishing awareness and management project.

📫 \_Add your GitHub / LinkedIn / email here\_



\---



\## License



Released under the MIT License. See `LICENSE` for details.



\---



<p align="center"><b>Stay sharp. Think before you click. 🛡️</b></p>

