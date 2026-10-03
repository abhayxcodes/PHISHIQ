

from __future__ import annotations

import re
from html import unescape
from urllib.parse import urlparse

from .brands import (
    EMAIL_INFO_REQUESTS,
    EMAIL_SUSPICIOUS_WORDS,
    EMAIL_URGENCY_PHRASES,
    INDIAN_PHISHING_PHRASES,
    SMS_KEYWORDS,
    SMS_URGENCY_PHRASES,
    SUSPICIOUS_EXTENSIONS,
)

URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>'\"]+")
EMAIL_RE = re.compile(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b")

def _contains_phrase(text: str, phrase: str) -> bool:
    escaped = re.escape(phrase.strip())
    if " " in phrase.strip():
        return re.search(rf"(?<!\w){escaped}(?!\w)", text, re.I) is not None
    return re.search(rf"\b{escaped}\b", text, re.I) is not None

def keyword_hits(text: str, words) -> list[str]:
    return [word for word in words if _contains_phrase(text, word)]

def extract_urls(text: str) -> list[str]:
    urls = []
    for raw in URL_RE.findall(text or ""):
        urls.append(raw.rstrip(".,;:!?)]}"))
    return urls

def email_rules(text: str) -> tuple[float, list[tuple[str, float]], list[str]]:
    text = unescape(text or "")
    lower = text.lower()
    points = 0.0
    reasons: list[tuple[str, float]] = []
    hard_flags: list[str] = []

    hits = keyword_hits(lower, EMAIL_SUSPICIOUS_WORDS)
    if hits:
        p = min(20.0, len(hits) * 4.0)
        points += p
        reasons.append((f"Suspicious email keywords: {', '.join(hits)}", p))

    hits = keyword_hits(lower, EMAIL_URGENCY_PHRASES)
    if hits:
        p = min(15.0, len(hits) * 5.0)
        points += p
        reasons.append((f"Urgency language: {', '.join(hits)}", p))

    hits = keyword_hits(lower, EMAIL_INFO_REQUESTS)
    if hits:
        p = min(25.0, len(hits) * 7.0)
        points += p
        reasons.append((f"Credential/payment request: {', '.join(hits)}", p))
        if any(_contains_phrase(lower, x) for x in ("send otp", "share otp", "enter password", "cvv")):
            hard_flags.append("credential request")

    urls = extract_urls(text)
    if len(urls) >= 2:
        points += 8
        reasons.append(("Multiple links found", 8))
    if urls:
        reasons.append((f"{len(urls)} URL(s) found in email", min(8, len(urls) * 2)))

    if re.search(r"(?i)\.(xyz|top|tk|gq|ml|cf|ga|click|zip)\b", text):
        points += 15
        reasons.append(("Suspicious link TLD detected", 15))

    if any(ext in lower for ext in SUSPICIOUS_EXTENSIONS):
        points += 18
        reasons.append(("Potentially dangerous attachment/file extension mentioned", 18))

    if re.search(r"(?i)<a\b[^>]*href\s*=\s*['\"]([^'\"]+)['\"][^>]*>(.*?)</a>", text, re.S):
        for href, label in re.findall(
            r"(?i)<a\b[^>]*href\s*=\s*['\"]([^'\"]+)['\"][^>]*>(.*?)</a>", text, re.S
        ):
            href_host = urlparse(href).hostname or ""
            label_url = URL_RE.search(unescape(re.sub("<[^>]+>", " ", label)))
            if label_url and href_host:
                shown_host = urlparse(label_url.group(0)).hostname or ""
                if shown_host and shown_host.lower() != href_host.lower():
                    points += 25
                    reasons.append(("Displayed link differs from destination", 25))
                    hard_flags.append("link mismatch")
                    break

    if re.search(r"(?i)\bdear\s+(customer|user)\b", lower):
        points += 5
        reasons.append(("Generic greeting used", 5))

    if re.search(r"(?i)(suspended|blocked|legal action)", lower) and re.search(
        r"(?i)(urgent|immediately|act now|verify)", lower
    ):
        points += 18
        reasons.append(("Threat plus urgency combination", 18))
        hard_flags.append("urgency + threat")

    sender = re.search(r"(?im)^\s*from:\s*[^\n<]*<[^>]*@([^>\s]+)>", text)
    reply = re.search(r"(?im)^\s*reply-to:\s*[^\n<]*<[^>]*@([^>\s]+)>", text)
    if sender and reply and sender.group(1).lower() != reply.group(1).lower():
        points += 18
        reasons.append(("From and Reply-To domains differ", 18))
        hard_flags.append("reply-to mismatch")

    return min(points, 100.0), reasons, hard_flags

def sms_rules(text: str, sender: str = "") -> tuple[float, list[tuple[str, float]], list[str]]:
    text = text or ""
    lower = text.lower()
    points = 0.0
    reasons: list[tuple[str, float]] = []
    hard_flags: list[str] = []

    hits = keyword_hits(lower, SMS_KEYWORDS)
    # "free" alone is benign in normal conversation; only score it when it
    # appears with a prize/reward/gift/click/link pattern.
    if "free" in hits and not re.search(
        r"(?i)\b(free\s+(?:gift|prize|reward|cash|voucher)|(?:gift|prize|reward|cash|voucher)\s+is\s+free)\b",
        lower,
    ):
        hits.remove("free")
    if hits:
        p = min(22.0, len(hits) * 3.5)
        points += p
        reasons.append((f"SMS risk keywords: {', '.join(hits)}", p))

    hits = keyword_hits(lower, SMS_URGENCY_PHRASES)
    if hits:
        p = min(15.0, len(hits) * 5.0)
        points += p
        reasons.append((f"Urgency language: {', '.join(hits)}", p))

    if any(_contains_phrase(lower, phrase) for phrase in INDIAN_PHISHING_PHRASES):
        points += 15
        reasons.append(("Indian-context phishing/scam pattern detected", 15))

    if re.search(r"(?i)\b(?:share|send|tell|give)\s+(?:me\s+)?(?:the\s+)?otp\b", lower) or \
       re.search(r"(?i)\botp\s+(?:is|code)\b.*(?:http|www\.)", lower):
        points += 30
        reasons.append(("OTP-sharing request detected", 30))
        hard_flags.append("otp request")

    if any(ext in lower for ext in SUSPICIOUS_EXTENSIONS):
        points += 18
        reasons.append(("Potentially dangerous file extension mentioned", 18))

    if re.search(r"(?i)\b(?:electricity|bill)\b.*\bdisconnect\b", lower):
        points += 12
        reasons.append(("Electricity-disconnect scam pattern", 12))

    if sender:
        sender_clean = sender.strip()
        if re.fullmatch(r"\+?\d{10,13}", sender_clean):
            bank_words = ("sbi", "hdfc", "icici", "axis", "bank", "kyc")
            if any(_contains_phrase(lower, w) for w in bank_words):
                points += 20
                reasons.append(("Numeric sender claims a bank/service", 20))
                hard_flags.append("sender mimicry")

    return min(points, 100.0), reasons, hard_flags
