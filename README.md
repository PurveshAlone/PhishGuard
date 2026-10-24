# PhishGuard — Phishing URL Risk Checker

## About the Project
PhishGuard is a Python-based cybersecurity project that analyzes URLs and identifies potentially suspicious patterns using rule-based heuristics. It provides an explainable risk score to help users understand common phishing indicators.

## Features
- URL validation and parsing
- Detection of suspicious URL patterns
- Checks for IP-address-based URLs and unusual URL structures
- Explainable risk scoring
- Simple interactive interface built with Streamlit
- Automated unit tests
- Designed to analyze URL text without automatically visiting submitted URLs

## Technologies Used
- Python
- Streamlit
- Regular Expressions
- URL Parsing
- Unit Testing

## Project Structure
```text
phishguard-url-checker/
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
└── tests/
    └── test_analyzer.py
```

## Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/PurveshAlone/phishguard-url-checker.git
   ```

2. Open the project folder:
   ```bash
   cd phishguard-url-checker
   ```

3. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   ```

   On Windows:
   ```bash
   .venv\Scripts\activate
   ```

4. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

5. Run the application:
   ```bash
   python -m streamlit run app.py
   ```

## Testing
Run the unit tests with:

```bash
python -m unittest discover -s tests -v
```

## Security and Limitations
PhishGuard uses heuristic rules to flag potentially suspicious URL characteristics. Its score is an indicator for awareness and is not a confirmed phishing verdict or a probability of attack.

The application is designed not to fetch or visit submitted URLs automatically. False positives and false negatives are possible. Do not rely on this tool alone to decide whether a website is safe.

## Project Purpose
This project was developed for cybersecurity learning, Python practice, and phishing-awareness education.

## Author
Purvesh Alone — PhishGuard

## Disclaimer
For educational and defensive cybersecurity purposes only.
