"""URL/text feature extraction used by training and inference."""

from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import urlparse

import numpy as np
import tldextract
from rapidfuzz.fuzz import ratio

_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)

from .brands import ( 
    BRANDS,
    CREDENTIAL_KEYWORDS,
    SHORTENERS,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_TLDS,
    TRUSTED_DOMAINS,
)

_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")

def normalize_url(url: str) -> str:
    """Return a parseable URL without changing its path/host semantics."""
    value = (url or "").strip()
    if not value:
        return ""
    if _URL_SCHEME_RE.match(value):
        return value
    return "http://" + value

def _registered_domain(host: str) -> str:
    ext = _TLD_EXTRACT(host or "")
    return getattr(ext, "top_domain_under_public_suffix", "") or getattr(
        ext, "registered_domain", ""
    ) or (f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ext.domain)

def _is_ip(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        if host.lower().startswith("0x"):
            ipaddress.ip_address(int(host, 16))
            return True
        if host.isdigit() and int(host) <= 0xFFFFFFFF:
            ipaddress.ip_address(int(host))
            return True
    except (ValueError, OverflowError):
        pass
    return False

def _host_ip(host: str) -> bool:
    if _is_ip(host):
        return True
    if host and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return True
    return False

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = [value.count(c) / len(value) for c in set(value)]
    return -sum(p * math.log2(p) for p in counts if p > 0)

def _domain_label(host: str) -> str:
    ext = _TLD_EXTRACT(host or "")
    return ext.domain or ""

def _host_tokens(host: str) -> list[str]:
    return [x for x in re.split(r"[.\-_]", host.lower()) if x]

def _brand_wrong_place(host: str, path: str) -> bool:
    registered = _registered_domain(host).lower()
    combined = f"{host.lower()} {path.lower()}"
    for brand, real_domains in BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", combined):
            if not any(registered == d or registered.endswith("." + d) for d in real_domains):
                return True
    return False

def _typosquat(host: str) -> bool:
    if not host or _is_ip(host):
        return False
    labels = _host_tokens(host)
    for label in labels:
        if len(label) < 4:
            continue
        normalized = label.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "5": "s"}))
        for brand in BRANDS:
            if ratio(normalized, brand) >= 80 and normalized != brand:
                return True
            if abs(len(normalized) - len(brand)) <= 2 and ratio(normalized, brand) >= 70:
                return True
    return False

def _shortener(host: str) -> bool:
    return (host.lower()[4:] if host.lower().startswith("www.") else host.lower()) in SHORTENERS

def analyze_url(url: str) -> dict:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("URL is empty.")
    normalized = normalize_url(raw)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("URL has no valid hostname.")

    registered = _registered_domain(host).lower()
    label = _domain_label(host)
    subdomain = (_TLD_EXTRACT(host).subdomain or "").lower()
    tokens = _host_tokens(host)
    path = parsed.path or ""
    query = parsed.query or ""
    tld = (_TLD_EXTRACT(host).suffix or "").lower()
    query_params = [p for p in query.split("&") if p]

    ip_host = _host_ip(host)
    punycode = "xn--" in host
    non_ascii = any(ord(c) > 127 for c in raw)
    suspicious_tld = tld in SUSPICIOUS_TLDS
    brand_wrong = _brand_wrong_place(host, path)
    typo = False if registered in TRUSTED_DOMAINS else _typosquat(host)
    shortener = _shortener(host)
    credential_hits = [
        k for k in CREDENTIAL_KEYWORDS
        if re.search(rf"\b{re.escape(k)}\b", f"{host} {path}", re.I)
    ]
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("URL contains an invalid port.")
    nonstandard_port = port is not None and port not in (80, 443)
    dangerous_extension = any(
        re.search(rf"{re.escape(ext)}(?:$|[?#])", path, re.I)
        for ext in SUSPICIOUS_EXTENSIONS
    )
    domain_entropy = _entropy(label)
    vowels = sum(c in "aeiou" for c in label.lower())
    consonants = sum(c.isalpha() and c.lower() not in "aeiou" for c in label.lower())

    features = np.array([
        len(raw),                                  # 1 URL length
        len(host),                                 # 2 host length
        len(path),                                 # 3 path length
        raw.count("."),                            # 4 dots
        raw.count("-"),                            # 5 hyphens
        raw.count("_"),                            # 6 underscores
        raw.count("@"),                            # 7 @
        raw.count("%"),                            # 8 encoded chars
        raw.count("/"),                            # 9 slashes
        raw.count("?"),                            # 10 query marker
        raw.count("="),                            # 11 equals
        len(query_params),                         # 12 query params
        sum(c.isdigit() for c in raw),             # 13 digits
        sum(c.isupper() for c in raw),             # 14 uppercase
        sum(c.isalpha() for c in raw),             # 15 letters
        sum(c.isdigit() for c in raw) / max(len(raw), 1),  # 16 digit ratio
        len(_TOKEN_RE.findall(host)),              # 17 host tokens
        len(subdomain.split(".")) if subdomain else 0,      # 18 subdomain count
        len(label),                                # 19 registered label length
        max((len(x) for x in tokens), default=0),  # 20 longest host token
        sum(c == "-" for c in host),               # 21 host hyphens
        sum(c.isdigit() for c in host),            # 22 host digits
        int(suspicious_tld),                       # 23 suspicious TLD
        int(brand_wrong),                           # 24 brand wrong place
        int(typo),                                 # 25 typosquat
        int(punycode),                              # 26 punycode
        int(non_ascii),                             # 27 non-ASCII
        int(shortener),                             # 28 URL shortener
        len(credential_hits),                       # 29 credential keyword count
        int(nonstandard_port),                      # 30 nonstandard port
        int(parsed.scheme.lower() in {"data", "javascript"}), # 31 dangerous scheme
        int("//" in path),                          # 32 double slash in path
        int(dangerous_extension),                   # 33 dangerous extension
        domain_entropy,                             # 34 domain entropy
        vowels / max(consonants, 1),                # 35 vowel/consonant ratio
        int(len(raw) > 75),                         # 36 long URL
    ], dtype=float)

    hard_flags = []
    if "@" in raw:
        hard_flags.append("@ in URL")
    if ip_host:
        hard_flags.append("IP-address host")
    if punycode or non_ascii:
        hard_flags.append("punycode/homoglyph")
    if brand_wrong:
        hard_flags.append("brand in wrong place")
    if typo:
        hard_flags.append("possible typosquatting")
    if credential_hits and suspicious_tld:
        hard_flags.append("credential keyword + suspicious TLD")

    trusted = registered in TRUSTED_DOMAINS

    return {
        "features": features,
        "normalized": normalized,
        "host": host,
        "registered_domain": registered,
        "path": path,
        "tld": tld,
        "trusted": trusted,
        "hard_flags": hard_flags,
        "signals": {
            "ip_host": ip_host,
            "punycode": punycode,
            "non_ascii": non_ascii,
            "brand_wrong_place": brand_wrong,
            "typosquat": typo,
            "shortener": shortener,
            "credential_hits": credential_hits,
            "suspicious_tld": suspicious_tld,
            "nonstandard_port": nonstandard_port,
            "dangerous_extension": dangerous_extension,
        },
    }

def extract_features(url: str) -> np.ndarray:
    return analyze_url(url)["features"]

# Kept as compatibility helpers for older imports. The production email/SMS
# models now use text pipelines directly rather than these hand-made vectors.
def extract_email_features(email_text: str) -> list[float]:
    text = email_text or ""
    words = text.split()
    n = max(len(text), 1)
    total_words = max(len(words), 1)
    return [
        float(len(text)),
        float(len(words)),
        float(len(set(words))),
        float(len(re.findall(r"https?://", text, re.I))),
        float(sum(c.isdigit() for c in text)),
        float(sum(c.isupper() for c in text)),
        float(sum(1 for w in ("verify", "login", "password", "bank", "account", "otp") if re.search(rf"\b{w}\b", text, re.I))),
        float(len(text)) / total_words,
        float(sum(c.isdigit() for c in text)) / n,
    ]

def extract_sms_features(sms: str) -> list[float]:
    text = sms or ""
    words = text.split()
    n = max(len(text), 1)
    total_words = max(len(words), 1)
    return [
        float(len(text)),
        float(len(words)),
        float(len(re.findall(r"https?://", text, re.I))),
        float(sum(c.isdigit() for c in text)),
        float(sum(c.isupper() for c in text)),
        float(sum(1 for w in ("verify", "login", "bank", "otp", "kyc") if re.search(rf"\b{w}\b", text, re.I))),
        float(len(text)) / total_words,
        float(sum(c.isdigit() for c in text)) / n,
    ]
