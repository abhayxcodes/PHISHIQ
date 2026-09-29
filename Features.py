import re
import numpy as np
from urllib.parse import urlparse

# -----------------------------
# Trusted Legitimate Domains
# -----------------------------
LEGIT_DOMAINS = {
    "google.com",
    "https://www.github.com",
    "amazon.in",
    "microsoft.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "stackoverflow.com",
    "openai.com",
    "apple.com",
    "netflix.com"
}


# -----------------------------
# URL Normalization
# -----------------------------
def normalize_url(url):

    url = url.strip().lower()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


# -----------------------------
# Feature Extraction
# -----------------------------
def extract_features(url):

    try:

        url = normalize_url(url)

        parsed = urlparse(url)

        domain = parsed.netloc.replace("www.", "")

        # ----------------------------------
        # Legit Website Protection Logic
        # ----------------------------------

        # Exact trusted domains
        if domain in LEGIT_DOMAINS:

            # very safe feature vector
            return np.array([
                0,0,1,0,0,
                0,0,0,0,0,
                0,0,0,0,0,
                0,1,0,1,0,
                1,0,0,2,0,
                3,0,0,0,0,
                1,0,0,0,0,
                0,0,0,0,0,
                0,0,0,0,5,
                10,0,0,5,5,
                0
            ], dtype=float)

        features = []

        # -----------------------------
        # Basic Features
        # -----------------------------

        features.append(len(url))                             # 1
        features.append(url.count('.'))                       # 2
        features.append(1 if parsed.scheme == "https" else 0) # 3
        features.append(len(parsed.netloc))                   # 4
        features.append(len(parsed.path))                     # 5

        # -----------------------------
        # Symbols
        # -----------------------------

        features.append(url.count('-'))                       # 6
        features.append(url.count('_'))                       # 7

        # Removed slash feature (false positives)
        features.append(0)                                    # 8

        # Removed query symbols importance
        features.append(0)                                    # 9
        features.append(0)                                    # 10

        # -----------------------------
        # Suspicious Characters
        # -----------------------------

        features.append(url.count('@'))                       # 11
        features.append(url.count('&'))                       # 12
        features.append(url.count('!'))                       # 13
        features.append(url.count(' '))                       # 14
        features.append(url.count('~'))                       # 15

        # -----------------------------
        # Digits & Letters
        # -----------------------------

        digits = sum(c.isdigit() for c in url)
        letters = sum(c.isalpha() for c in url)

        features.append(digits)                               # 16
        features.append(letters)                              # 17
        features.append(sum(c.isupper() for c in url))        # 18
        features.append(sum(c.islower() for c in url))        # 19

        length = len(url) if len(url) > 0 else 1

        features.append(digits / length)                      # 20
        features.append(letters / length)                     # 21

        # -----------------------------
        # Safer Keyword Detection
        # -----------------------------

        risky_keywords = [
            'verify-account',
            'secure-login',
            'bank-update',
            'free-gift',
            'confirm-password'
        ]

        features.append(
            sum(word in url.lower() for word in risky_keywords)
        )                                                     # 22

        # -----------------------------
        # IP Address Detection
        # -----------------------------

        features.append(
            1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url)
            else 0
        )                                                     # 23

        # -----------------------------
        # Domain Structure
        # -----------------------------

        features.append(len(parsed.netloc.split('.')))        # 24

        features.append(
            1 if '-' in parsed.netloc else 0
        )                                                     # 25

        # -----------------------------
        # TLD Length
        # -----------------------------

        tld = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''

        features.append(len(tld))                             # 26

        # -----------------------------
        # Double Slash Trick
        # -----------------------------

        features.append(
            1 if '//' in parsed.path else 0
        )                                                     # 27

        # -----------------------------
        # Path Depth
        # -----------------------------

        features.append(len(parsed.path.split('/')))          # 28

        # -----------------------------
        # Query Length Removed
        # -----------------------------

        features.append(0)                                    # 29
        features.append(0)                                    # 30

        # -----------------------------
        # Character Repetition
        # -----------------------------

        features.append(
            max([url.count(c) for c in set(url)]) if url else 0
        )                                                     # 31

        # -----------------------------
        # Entropy
        # -----------------------------

        prob = [url.count(c)/length for c in set(url)]

        entropy = -sum([
            p*np.log2(p) for p in prob if p > 0
        ])

        # normalized entropy
        features.append(entropy / 8)                          # 32

        # -----------------------------
        # Tricks
        # -----------------------------

        features.append(
            1 if 'https' in url.replace("https://", "")
            and 'http' in url else 0
        )                                                     # 33

        features.append(
            1 if 'www' in parsed.path else 0
        )                                                     # 34

        features.append(
            1 if len(parsed.netloc) > 50 else 0
        )                                                     # 35

        # -----------------------------
        # Length Flags
        # -----------------------------

        features.append(1 if len(url) > 75 else 0)           # 36
        features.append(1 if len(url) < 20 else 0)           # 37

        # -----------------------------
        # Numeric Domain
        # -----------------------------

        features.append(
            1 if any(c.isdigit() for c in parsed.netloc)
            else 0
        )                                                    # 38

        # -----------------------------
        # Dangerous Extensions
        # -----------------------------

        features.append(
            1 if any(ext in url for ext in ['.exe','.zip','.rar'])
            else 0
        )                                                    # 39

        # -----------------------------
        # URL Structure
        # -----------------------------

        features.append(url.count(':'))                      # 40
        features.append(url.count(';'))                      # 41
        features.append(url.count('%'))                      # 42

        # -----------------------------
        # Encoded / Hex Patterns
        # -----------------------------

        features.append(
            len(re.findall(r'[A-F0-9]{8,}', url))
        )                                                    # 43

        features.append(
            len(re.findall(r'\d{4,}', url))
        )                                                    # 44

        # -----------------------------
        # Protocol Length
        # -----------------------------

        features.append(len(parsed.scheme))                  # 45

        # -----------------------------
        # Hostname Length
        # -----------------------------

        features.append(
            len(parsed.hostname) if parsed.hostname else 0
        )                                                    # 46

        # -----------------------------
        # Prefix/Suffix Tricks
        # -----------------------------

        features.append(
            1 if parsed.netloc.startswith('www-') else 0
        )                                                    # 47

        features.append(
            1 if parsed.netloc.endswith('-') else 0
        )                                                    # 48

        # -----------------------------
        # Vowels / Consonants
        # -----------------------------

        features.append(
            sum(c in 'aeiou' for c in url.lower())
        )                                                    # 49

        features.append(
            sum(c.isalpha() and c not in 'aeiou'
            for c in url.lower())
        )                                                    # 50

        # -----------------------------
        # Deep Subdomain
        # -----------------------------

        features.append(
            1 if len(parsed.netloc.split('.')) > 3 else 0
        )                                                    # 51

        return np.array(features, dtype=float)

    except Exception as e:

        print("Feature extraction error:", e)

        return np.zeros(51)


################              Email           ###############################


import re
import math

def extract_email_features(email_text):

    email_text = email_text.lower()
    features = []

    words = email_text.split()
    total_words = len(words) if len(words) > 0 else 1

    # ---------- LENGTH FEATURES ----------
    features.append(len(email_text))                #1
    features.append(total_words)                    #2
    features.append(len(set(words)))                #3 unique words

    # ---------- LINK FEATURES ----------
    http_count = email_text.count("http")
    features.append(http_count)                     #4
    features.append(1 if http_count >= 2 else 0)    #5

    # ---------- DOMAIN FEATURES ----------
    features.append(1 if re.search(r'\.(xyz|top|tk|gq)', email_text) else 0)  #6
    features.append(len(re.findall(r'\.com', email_text)))                    #7
    features.append(len(re.findall(r'\.net', email_text)))                    #8

    # ---------- KEYWORD COUNTS ----------
    sus_words = ['urgent','verify','login','password','bank','account',
                 'click','update','confirm','suspend','security alert']

    urgent_words = ['immediately','act now','limited time',
                    'within 24 hours','suspended']

    info_words = ['enter password','send otp','credit card',
                  'debit card','cvv']

    sus_count = sum(1 for w in sus_words if w in email_text)
    urgent_count = sum(1 for w in urgent_words if w in email_text)
    info_count = sum(1 for w in info_words if w in email_text)

    features.append(sus_count)      #9
    features.append(urgent_count)   #10
    features.append(info_count)     #11

    # ---------- SYMBOL FEATURES ----------
    features.append(email_text.count('!'))  #12
    features.append(email_text.count('@'))  #13
    features.append(email_text.count('$'))  #14
    features.append(email_text.count('%'))  #15
    features.append(email_text.count('#'))  #16

    # ---------- DIGIT FEATURES ----------
    digits = sum(1 for c in email_text if c.isdigit())
    features.append(digits)                     #17
    features.append(digits / len(email_text))   #18 digit ratio

    # ---------- UPPERCASE SIGNAL ----------
    upper = sum(1 for c in email_text if c.isupper())
    features.append(upper)                      #19
    features.append(upper / len(email_text))    #20

    # ---------- IP URL ----------
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', email_text) else 0) #21

    # ---------- HTML ----------
    features.append(len(re.findall("<a", email_text)))    #22
    features.append(len(re.findall("<form", email_text))) #23

    # ---------- MONEY SIGNAL ----------
    features.append(1 if "rs" in email_text else 0)   #24
    features.append(1 if "usd" in email_text else 0)  #25

    # ---------- ENTROPY ----------
    prob = [float(email_text.count(c)) / len(email_text) for c in dict.fromkeys(list(email_text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    features.append(entropy)   #26

    # ---------- AVG WORD LENGTH ----------
    avg_word_len = sum(len(w) for w in words) / total_words
    features.append(avg_word_len)   #27

    # ---------- SHORT WORD RATIO ----------
    short_words = sum(1 for w in words if len(w) <= 3)
    features.append(short_words / total_words)   #28

    # ---------- LONG WORD RATIO ----------
    long_words = sum(1 for w in words if len(w) >= 10)
    features.append(long_words / total_words)    #29

    # ---------- REPETITION SIGNAL ----------
    features.append(total_words - len(set(words)))  #30 repeated words

    # ---------- QUESTION MARK ----------
    features.append(email_text.count('?'))   #31

    # ---------- COLON ----------
    features.append(email_text.count(':'))   #32

    # ---------- SEMICOLON ----------
    features.append(email_text.count(';'))   #33

    # ---------- DASH ----------
    features.append(email_text.count('-'))   #34

    # ---------- UNDERSCORE ----------
    features.append(email_text.count('_'))   #35

    # ---------- BRACKETS ----------
    features.append(email_text.count('('))   #36
    features.append(email_text.count(')'))   #37

    # ---------- NEWLINE ----------
    features.append(email_text.count('\n'))  #38

    # ---------- EMAIL PATTERN ----------
    features.append(len(re.findall(r'\S+@\S+', email_text)))  #39

    # ---------- URL LENGTH AVG ----------
    urls = re.findall(r'http\S+', email_text)
    avg_url_len = sum(len(u) for u in urls)/len(urls) if urls else 0
    features.append(avg_url_len)   #40

    # ---------- SUSPICIOUS FILE ----------
    features.append(1 if ".exe" in email_text else 0)   #41
    features.append(1 if ".zip" in email_text else 0)   #42
    features.append(1 if ".apk" in email_text else 0)   #43

    # ---------- OTP SIGNAL ----------
    features.append(1 if "otp" in email_text else 0)   #44

    # ---------- VERIFY SIGNAL ----------
    features.append(1 if "verify" in email_text else 0)   #45

    # ---------- LOGIN SIGNAL ----------
    features.append(1 if "login" in email_text else 0)   #46

    # ---------- CLICK SIGNAL ----------
    features.append(1 if "click" in email_text else 0)   #47

    # ---------- ACCOUNT SIGNAL ----------
    features.append(1 if "account" in email_text else 0)   #48

    # ---------- PASSWORD SIGNAL ----------
    features.append(1 if "password" in email_text else 0)   #49

    # ---------- BANK SIGNAL ----------
    features.append(1 if "bank" in email_text else 0)   #50

    # ---------- FINAL LENGTH RATIO ----------
    features.append(len(email_text)/total_words)   #51

    return features





    #######################              SMS                ###########################



import re
import math
import re
import math

def extract_sms_features(sms):

    sms_lower = sms.lower()
    features = []

    words = sms_lower.split()
    total_words = len(words) if len(words) > 0 else 1


    # ===== BASIC LENGTH =====
    features.append(len(sms_lower))                 #1
    features.append(total_words)                    #2
    features.append(len(set(words)))                #3


    # ===== URL =====
    http_count = sms_lower.count("http")
    features.append(http_count)                     #4
    features.append(1 if http_count >= 2 else 0)    #5
    features.append(len(re.findall(r'www\.', sms_lower))) #6
    features.append(len(re.findall(r'bit\.ly', sms_lower))) #7
    features.append(len(re.findall(r'tinyurl', sms_lower))) #8


    # ===== SUSPICIOUS DOMAIN =====
    features.append(1 if re.search(r'\.(xyz|top|tk|gq)', sms_lower) else 0) #9


    # ===== KEYWORDS =====
    keywords = ["urgent","verify","update","click","login",
                "bank","account","suspended","winner","free",
                "prize","otp"]

    keyword_count = sum(1 for k in keywords if k in sms_lower)
    features.append(keyword_count)                  #10


    # ===== URGENCY =====
    urgency_words = ["immediately","now","within 24 hours","act fast"]
    urgency_count = sum(1 for u in urgency_words if u in sms_lower)
    features.append(urgency_count)                  #11


    # ===== FAKE PATTERN =====
    fake_words = ["secure-login","verify-account","update-info"]
    fake_count = sum(1 for f in fake_words if f in sms_lower)
    features.append(fake_count)                     #12


    # ===== SYMBOLS =====
    features.append(sms_lower.count('!'))           #13
    features.append(sms_lower.count('@'))           #14
    features.append(sms_lower.count('$'))           #15
    features.append(sms_lower.count('%'))           #16
    features.append(sms_lower.count('#'))           #17
    features.append(sms_lower.count('?'))           #18


    # ===== DIGITS =====
    digits = sum(c.isdigit() for c in sms_lower)
    features.append(digits)                         #19
    features.append(digits / len(sms_lower))        #20


    # ===== UPPERCASE =====
    upper = sum(c.isupper() for c in sms)
    features.append(upper)                          #21
    features.append(upper / len(sms))               #22


    # ===== MONEY =====
    features.append(1 if "rs" in sms_lower else 0)  #23
    features.append(1 if "₹" in sms_lower else 0)   #24
    features.append(1 if "usd" in sms_lower else 0) #25


    # ===== PHONE =====
    features.append(len(re.findall(r'\d{10}', sms_lower))) #26


    # ===== EMAIL =====
    features.append(len(re.findall(r'\S+@\S+', sms_lower))) #27


    # ===== IMPORTANT WORD FLAGS =====
    features.append(1 if "otp" in sms_lower else 0)     #28
    features.append(1 if "verify" in sms_lower else 0)  #29
    features.append(1 if "login" in sms_lower else 0)   #30
    features.append(1 if "click" in sms_lower else 0)   #31
    features.append(1 if "account" in sms_lower else 0) #32
    features.append(1 if "bank" in sms_lower else 0)    #33
    features.append(1 if "free" in sms_lower else 0)    #34
    features.append(1 if "winner" in sms_lower else 0)  #35
    features.append(1 if "prize" in sms_lower else 0)   #36


    # ===== WORD STRUCTURE =====
    short_words = sum(1 for w in words if len(w) <= 3)
    features.append(short_words / total_words)      #37

    long_words = sum(1 for w in words if len(w) >= 10)
    features.append(long_words / total_words)       #38

    avg_len = sum(len(w) for w in words) / total_words
    features.append(avg_len)                        #39

    features.append(total_words - len(set(words)))  #40


    # ===== FORMATTING =====
    features.append(sms_lower.count('-'))           #41
    features.append(sms_lower.count('_'))           #42
    features.append(sms_lower.count('\n'))          #43


    # ===== FILE ATTACK =====
    features.append(1 if ".apk" in sms_lower else 0) #44
    features.append(1 if ".exe" in sms_lower else 0) #45
    features.append(1 if ".zip" in sms_lower else 0) #46


    # ===== URL AVG LENGTH =====
    urls = re.findall(r'http\S+', sms_lower)
    avg_url_len = sum(len(u) for u in urls)/len(urls) if urls else 0
    features.append(avg_url_len)                    #47


    # ===== ENTROPY =====
    prob = [float(sms_lower.count(c)) / len(sms_lower)
            for c in dict.fromkeys(list(sms_lower))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    features.append(entropy)                        #48


    # ===== MORE SYMBOLS =====
    features.append(sms_lower.count(':'))           #49
    features.append(sms_lower.count(';'))           #50
    features.append(sms_lower.count('('))           #51
    features.append(sms_lower.count(')'))           #52


    # ===== FINAL RATIO =====
    features.append(len(sms_lower)/total_words)     #53


    return features