"""Offline, explainable URL heuristics. This module never makes network requests."""
from urllib.parse import urlsplit
import ipaddress
import re

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
SUSPICIOUS_TERMS = {
    "login", "verify", "verification", "secure", "account", "password",
    "signin", "sign-in", "update", "wallet", "billing", "recover"
}
BRANDLIKE_TERMS = {
    "paypal", "microsoft", "apple", "google", "amazon", "facebook",
    "instagram", "netflix", "outlook", "bank"
}
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _add(rules, name, points, reason):
    rules.append({"name": name, "points": points, "reason": reason})


def analyze_url(raw_url: str) -> dict:
    """Analyze URL text only. Never resolve or connect to the hostname."""
    if not isinstance(raw_url, str):
        return {"valid": False, "error": "Input must be text."}

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_url):
        return {"valid": False, "error": "URL contains control characters."}

    value = raw_url.strip()
    if not value:
        return {"valid": False, "error": "Enter a URL."}
    if len(value) > MAX_URL_LENGTH:
        return {"valid": False, "error": f"URL is too long (maximum {MAX_URL_LENGTH} characters)."}

    # Reject embedded whitespace instead of silently normalizing ambiguous input.
    if any(ch.isspace() for ch in value):
        return {"valid": False, "error": "URL must not contain unescaped whitespace."}

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            return {"valid": False, "error": "Only explicit http:// or https:// URLs are accepted."}
        if not parsed.netloc:
            return {"valid": False, "error": "URL must include a hostname."}
        if parsed.username is not None or parsed.password is not None:
            # Keep this analyzable because user-info is itself a risk indicator.
            has_userinfo = True
        else:
            has_userinfo = False
        hostname = parsed.hostname
        if not hostname:
            return {"valid": False, "error": "Could not parse a hostname."}
        port = parsed.port  # Raises ValueError for malformed ports.
    except ValueError:
        return {"valid": False, "error": "Malformed URL or invalid port."}

    host = hostname.rstrip(".").lower()
    if not host:
        return {"valid": False, "error": "Hostname is empty."}

    # Reject malformed DNS-style labels while allowing IP literals.
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if not is_ip:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return {"valid": False, "error": "Hostname could not be parsed safely."}
        labels = ascii_host.split(".")
        if any(not label or not LABEL_RE.fullmatch(label) for label in labels):
            return {"valid": False, "error": "Hostname contains invalid DNS label syntax."}
        if len(ascii_host) > 253:
            return {"valid": False, "error": "Hostname is too long."}
    else:
        ascii_host = host
        labels = [host]

    rules = []
    score = 0

    if scheme != "https":
        _add(rules, "No HTTPS", 10, "The URL uses HTTP, so transport encryption is not indicated.")
    if has_userinfo:
        _add(rules, "User-info in authority", 25, "Text before @ can make the displayed URL misleading.")
    if is_ip:
        _add(rules, "IP address hostname", 15, "The hostname is an IP literal rather than a domain name.")
    if len(value) > 150:
        _add(rules, "Long URL", 10, "Long URLs can obscure the meaningful destination.")
    if len(labels) >= 5 and not is_ip:
        _add(rules, "Many hostname labels", 10, f"The hostname has {len(labels)} labels.")
    if len(host) > 60:
        _add(rules, "Long hostname", 10, "The hostname is unusually long.")
    if "xn--" in ascii_host:
        _add(rules, "Punycode hostname", 15, "Internationalized hostname encoding can be used in lookalike domains.")
    if host.count("-") >= 3:
        _add(rules, "Many hyphens in hostname", 8, "The hostname contains several hyphens.")
    if port is not None and port not in (80, 443):
        _add(rules, "Uncommon explicit port", 8, f"The URL specifies port {port}.")

    host_terms = set(re.findall(r"[a-z0-9]+", ascii_host))
    path_query = (parsed.path + "?" + parsed.query).lower()
    matched_sensitive = sorted(term for term in SUSPICIOUS_TERMS if term in path_query)
    if matched_sensitive:
        _add(rules, "Sensitive-action wording in path/query", 8,
             "Contains terms often seen in account or sign-in flows: " + ", ".join(matched_sensitive[:5]) + ".")

    brand_matches = sorted(term for term in BRANDLIKE_TERMS if term in host_terms)
    if brand_matches:
        # Only flag as a weak signal; presence in a domain is not proof of impersonation.
        _add(rules, "Brand-like term in hostname", 10,
             "Hostname includes a well-known service or brand-like term: " + ", ".join(brand_matches[:4]) + ".")

    score = min(100, sum(rule["points"] for rule in rules))
    return {
        "valid": True,
        "normalized_url": value,
        "hostname": ascii_host,
        "score": score,
        "rules": rules,
    }
