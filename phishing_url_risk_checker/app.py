import streamlit as st
from analyzer import analyze_url

st.set_page_config(page_title="Phishing URL Risk Checker", page_icon="🛡️", layout="centered")
st.title("🛡️ Phishing URL Risk Checker")
st.caption("Explainable indicators for human review — not a malware verdict.")

st.warning(
    "Safety note: This app analyzes the URL text only. It does not open, fetch, ping, "
    "resolve, or follow redirects to the submitted URL."
)

url = st.text_input(
    "Enter a URL",
    placeholder="https://example.com/account",
    max_chars=2048,
    help="Use a URL you are authorized to analyze. Do not enter passwords or other secrets."
)

if st.button("Analyze URL", type="primary"):
    result = analyze_url(url)
    if not result["valid"]:
        st.error(result["error"])
    else:
        score = result["score"]
        if score >= 60:
            label = "Higher risk indicators"
            st.error(label)
        elif score >= 30:
            label = "Some risk indicators"
            st.warning(label)
        else:
            label = "Fewer risk indicators detected"
            st.success(label)

        st.metric("Heuristic risk score", f'{score}/100')
        st.caption("This is a rule-based indicator score, not a probability.")
        st.write("**Submitted URL (shown as text):**")
        st.code(result["normalized_url"], language=None)

        st.subheader("Triggered rules")
        if result["rules"]:
            for rule in result["rules"]:
                st.write(f"- **+{rule['points']} points — {rule['name']}**: {rule['reason']}")
        else:
            st.write("No configured risk rules were triggered.")

        st.info(
            "A low score does not prove a URL is safe. A high score does not prove it is malicious. "
            "Verify the domain independently and use trusted security tools for further review."
        )

st.divider()
st.caption("Local heuristic tool • No external URL requests • No verdict guarantees")
