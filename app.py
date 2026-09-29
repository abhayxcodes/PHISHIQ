import flask 
import re 
import pandas as pd
import tldextract 
import language_tool_python
tool = language_tool_python.LanguageTool('en-US')
import pytesseract
import numpy as np
import warnings
warnings.filterwarnings("ignore")

from PIL import Image
from Machine_learning.Features import extract_features ,extract_email_features ,extract_sms_features

import joblib

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = joblib.load(r"C:\PHISHIQ\project_phishiq\Machine_learning\phishing_model.pkl")
email_model = joblib.load(r"C:\PHISHIQ\project_phishiq\Machine_learning\email_rf_model.pkl")
sms_model  = joblib.load(r"C:\PHISHIQ\project_phishiq\Machine_learning\sms_rf_model.pkl")
vectorizer = joblib.load(r"C:\PHISHIQ\project_phishiq\Machine_learning\sms_vectorizer.pkl")


app=flask.Flask(__name__)




@app.route('/')
def home():
    return flask.render_template('home.html')


#url logic
phish_words = ['login', 'verify', 'update', 'bank', 'secure', 'account']


@app.route('/url', methods=["GET", "POST"])

def form():
    result = None
    
  
  
    max_score =  10 + 10 + 10 + 10 + (len(phish_words) * 10) + 10 + 10 + 10 + 10 + 10 
    risk_percentage = 0
    ml_risk = 0
 
  
   

    if flask.request.method == "POST":
        url = flask.request.form['url']
        features = extract_features(url)
        features = features.reshape(1 ,-1)

        ml_prob = model.predict_proba(features)[0]* 100
        
       
     
       
        score = 0
        reasons = []

       
    

        if "@"in url:
            score += 10
            reasons.append("@ symbol dectected")
        

        if url.startswith("http://"):
            url = "http://" + url
            score += 10
            reasons.append("uncertain https")
           

        if url.count('.') > 3:
            score += 10
            reasons.append("dot count risk")
       

        if len(url) > 60:
            score += 10
            reasons.append("suspicious lenght")


        track_hits = [word for word in phish_words if word in url]

        score += sum(10 for word in phish_words if word in url.lower())
        reasons.append(f"Phishing words detected: {', '.join(track_hits)}")

        ext = tldextract.extract(url)
        domain = ext.domain
        subdomain = ext.subdomain

        if '-' in domain:
            score += 10
            reasons.append("- in domain dectected")

        if subdomain.count('.') >= 2:
            score += 10
            reasons.append("to many dot cout in subdomain dectected")

        if re.search(r'(\d{1,3}\.){3}\d{1,3}', url):
            score += 10
        reasons.append("unkown ip ")

        if url.count('/') > 5:
            score += 10
        reasons.append("to many slash count ")

        if re.match(r'http[s]?://[^/]+//', url):
            score += 10
        reasons.append("uncertain ip ")

        risk_percentage = round((score / max_score) * 100)


        ml_risk = (ml_prob )
        
       

     

        if risk_percentage <= 30:
            result =  "Low Risk ✅"
        elif risk_percentage <= 60:
            result = "Medium Risk ⚠"
        else:
            result =  "High Risk 🚨"


   
      
        





        return flask.render_template("dashboard.html",
                               result=result,
                               reasons=reasons,
               risk_percentage=risk_percentage,
                           ml_risk=ml_risk,
                            source="url"
            
                               )

    return flask.render_template("url.html")



#email logic 


@app.route('/email', methods=["GET", "POST"])
def email_check():

    result = None
    matches = []
    risk_percentage = 0
    ml_risk = 0 
    reasons = []
 
    
   
  
    sus_words = ['urgent', 'verify', 'login', 'password','bank', 'account', 
             'click', 'update','confirm', 'suspend', 'security alert']

    urgent_words = ['immediately', 'act now', 'limited time',
                    'within 24 hours', 'suspended']

    info_words = ['enter password', 'send otp','credit card',
                  'debit card','cvv']

    if flask.request.method == "POST":
       
        

        email_text = flask.request.form.get('email', '')
        screenshot = flask.request.files.get('screenshot')

        if screenshot and screenshot.filename != "":
            image = Image.open(screenshot)
            extracted_text = pytesseract.image_to_string(image)
            email_text += " " + extracted_text.lower()

        email_text = email_text.lower()
        features = extract_email_features(email_text)

     

        email_score = 0
        max_score = 10 + 10 +  (len(sus_words)*10) + (len(urgent_words)*10) + (len(info_words)*10)
        ml_prob = email_model.predict_proba([features])[0][1]*100






        track_hits = [word for word in sus_words if word in email_text]
        email_score += sum(10 for word in sus_words if word in email_text)
        reasons.append(f"sus words detected : {', '.join(track_hits)}")

     
        if email_text.count("http") >= 2:
            email_score += 10
            reasons.append("https  detected ")

      
        if re.search(r'\.(xyz|top|tk|gq)', email_text):
            email_score += 10
            reasons.append("wrong username detected ")




        track_hits = [word for word in urgent_words if word in email_text]
        email_score += sum(10 for word in urgent_words if word in email_text)
        reasons.append(f"urgent words detected: {', '.join(track_hits)}")

        track_hits = [word for word in info_words if word in email_text]
        email_score += sum(10 for word in info_words if word in email_text)
        reasons.append(f"scam words  detected : {', '.join(track_hits)} ")

        
        matches = tool.check(email_text)
        error_count = len(matches)

        if error_count >= 10:
            email_score += 30
        elif error_count >= 5:
            email_score += 20
        elif error_count >= 2:
            email_score += 10

        risk_percentage = round((email_score / max_score) * 100)
        ml_risk = (ml_prob , 2)

        if risk_percentage < 30:
            result = "Low Risk ✅"
        elif risk_percentage < 60:
            result = "Medium Risk ⚠"
        else:
            result =  "High Risk 🚨"

        return flask.render_template("dashboard.html",
                               email_text=email_text,
                  risk_percentage= risk_percentage,
                               result=result,
                               reasons=reasons,
                               ml_risk=ml_risk,
                               source="email")

    return flask.render_template('email.html')

#sms logic
keywords = ["urgent", "verify", "update", "click","login", "bank", "account", "suspended","winner", "free", "prize", "otp"] 
short_links = ["bit.ly", "tinyurl", "goo.gl", "t.co"]
urgent_words = ["immediately", "now", "within 24 hours", "act fast"]
fake_words = ["secure-login", "verify-account", "update-info"]



@app.route('/sms', methods=["GET", "POST"])
def sms_check():

    result = None
    reasons = []



    if flask.request.method == "POST":
        sms = flask.request.form['sms']
        screenshot = flask.request.files.get('screenshot')



        screenshot = flask.request.files.get("screenshot")
        if screenshot and screenshot.filename != "":
            image = Image.open(screenshot.stream)
            extracted_text = pytesseract.image_to_string(image)
            sms = (sms or "") + "\n" + extracted_text



        sms_lower = sms.lower()
        features = extract_sms_features(sms)
        score = 0
        risk_percentage = 0
        max_score = 10  + 10 + 10 +  (len(keywords)*10) + (len(short_links)*10) + (len(urgent_words)*10) + (len(fake_words)*10)
        
        ml_prob = float(sms_model.predict_proba(vectorizer.transform([sms]))[0][1]* 100)




        track_hits = [word for word in keywords if word in sms_lower]
        score += sum(10 for word in keywords if word in sms.lower())
        reasons.append(f"wrong keywords : {', '.join(track_hits)}")

        
        if re.search(r"http[s]?://|www\.", sms_lower):
            score += 10;
            reasons.append("uncertain url ")



            
        track_hits = [word for word in short_links if word in sms_lower]
        score += sum(10 for word in short_links if word in sms.lower())
        reasons.append(f"shorts links dectects : {', '.join(track_hits)} ")
        
        digits = sum(c.isdigit() for c in sms)
        if digits > 6:
            score += 10
            reasons.append("digit in sms ")


        
        if sms.isupper() and len(sms) > 15:
            score += 10
            reasons.append("lenght of sms is suspcious ")

        
        track_hits = [word for word in urgent_words if word in sms_lower]
        score +=  sum(10 for word in urgent_words if word in sms.lower())
        reasons.append(f"fake words detected : {', '.join(track_hits)}")

        track_hits = [word for word in fake_words if word in sms_lower]
        score +=  sum(10 for word in fake_words if word in sms.lower())
        reasons.append(f"fake words detected : {', '.join(track_hits)} ")




        risk_percentage = round((score / max_score) * 100)
        ml_risk = (ml_prob,2)



        if risk_percentage < 30:
            result = "Low Risk ✅"
        elif risk_percentage < 60:
            result = "Medium Risk ⚠"
        else:
            result = "High Risk 🚨"

        

        return flask.render_template("dashboard.html",
                               sms = sms ,
                               result=result,
                               reasons=reasons,
                risk_percentage=risk_percentage,
                               ml_risk=ml_risk,
                               source="sms")

    return flask.render_template("sms.html")






@app.route('/recovery', methods=["GET", "POST"])
def recovery():

    recovery_type = None
    steps = []

    if flask.request.method == "POST":
        recovery_type = flask.request.form.get("type")

        if recovery_type == "password":
            steps = [
                "Immediately change your password on the real website",
                "Enable 2FA (Two Factor Authentication)",
                "Logout from all devices",
                "Check login activity and remove unknown sessions"
            ]

        elif recovery_type == "bank":
            steps = [
                "Call your bank helpline immediately",
                "Block your debit/credit card",
                "Freeze online banking temporarily",
                "Immediately call Cyber Crime Helpline: 1930"
            ]

        elif recovery_type == "otp":
            steps = [
                "Immediately contact your bank",
                "Block your account temporarily",
                "Monitor transactions carefully"
            ]

        elif recovery_type == "device":
            steps = [
                "Disconnect from internet",
                "Run full antivirus scan",
                "Uninstall unknown applications",
                "Change passwords from another safe device"
            ]

    return flask.render_template("recovery.html", steps=steps)



if __name__ == "__main__":
    app.run(debug=True)






    



        
