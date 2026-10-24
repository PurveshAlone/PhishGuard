# Phishing URL Risk Checker

An offline, explainable heuristic tool for phishing-awareness training. It flags URL characteristics for human review; it cannot prove that a URL is malicious or safe.

## Features
- Python URL parsing (`urllib.parse`) and bounded regular expressions
- Explainable, rule-based score (0–100)
- Rejects unsupported schemes, malformed hostnames, whitespace/control characters, and oversized input
- Does **not** open, fetch, ping, resolve, crawl, or follow redirects to submitted URLs
- Unit tests for core behavior and edge cases

## Run locally
Use Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python -m unittest discover -s tests -v
streamlit run app.py
```

## Risk score
The score is the sum of configured heuristic points, capped at 100. It is not a probability or reputation verdict. The rules are intentionally explainable and may produce false positives and false negatives.

## Security design
- No outbound network requests for submitted URLs (SSRF prevention by design)
- No user-controlled HTML rendering; URLs and reasons are displayed as text
- Explicit scheme allowlist (`http`, `https`)
- Input length and control-character limits
- Standard-library URL parsing and bounded regex patterns
- No URL submission logging or persistence in this app

## Limitations
- Heuristics are not a substitute for threat-intelligence feeds, browser protections, DNS reputation, certificate checks, or analyst review.
- HTTPS, short URLs, or familiar-looking domains do not guarantee safety.
- The app does not validate ownership, reputation, page contents, redirects, or the actual destination behind a shortened URL.
- Brand-like terms can create false positives; legitimate login pages can look suspicious.
- The score thresholds are illustrative and need evaluation against a representative labeled dataset before operational use.

## Suggested synthetic tests
Use reserved example domains and documentation IP addresses, for example:
- `https://example.com`
- `http://example.com/account/verify`
- `https://192.0.2.10/login`
- `https://trusted.example@evil.example/`
- `https://login.account.verify.example.test/path`

Do not test by visiting suspicious links. This app does not need to visit them.

## Production checklist
- Pin and routinely update dependencies; run `pip-audit` in CI.
- Keep Streamlit and Python patched.
- Set resource and request limits at the hosting layer.
- Do not enable debug mode in production.
- Use HTTPS for the deployed application.
- Review platform access controls and secrets before deployment.
- Add CI tests and evaluate false positives/negatives on a labeled, safe dataset.
