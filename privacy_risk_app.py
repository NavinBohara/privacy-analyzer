import streamlit as st
import json
import os
from privacy_risk_analyzer import analyze_apk

st.title("AppGuardian - Privacy Risk Analyzer for Android APKs")

uploaded_file = st.file_uploader("Upload an APK file", type=["apk"])

if uploaded_file is not None:
    apk_path = os.path.join("/tmp", uploaded_file.name)
    with open(apk_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.info(f"Analyzing {uploaded_file.name}...")
    report = analyze_apk(apk_path)

    # Human-readable, clear summary
    st.header(f"App Name: {report['app_name']}")
    st.markdown(f"**Package:** `{report['package']}`")

    # Risk Level Box
    if report['risk_level'] == 'High':
        st.error(f"Risk Score: {report['risk_score']} (HIGH RISK)\n\nThis app requests many sensitive permissions and/or uses sensitive APIs. Proceed with caution.")
    elif report['risk_level'] == 'Medium':
        st.warning(f"Risk Score: {report['risk_score']} (MEDIUM RISK)\n\nThis app requests some sensitive permissions or uses sensitive APIs.")
    else:
        st.success(f"Risk Score: {report['risk_score']} (LOW RISK)\n\nThis app requests few sensitive permissions and uses few sensitive APIs.")

    st.markdown("---")
    st.subheader("High Risk Permissions")
    st.caption("These permissions can access sensitive data or device features:")
    if report['high_risk_permissions']:
        st.markdown("\n".join([f"- `{p}`" for p in report['high_risk_permissions']]))
    else:
        st.write("None detected.")

    st.subheader("Sensitive API Usage Detected")
    st.caption("The app's code references these sensitive Android APIs:")
    if report['sensitive_apis']:
        st.markdown("\n".join([f"- `{a}`" for a in report['sensitive_apis']]))
    else:
        st.write("None detected.")

    st.subheader("All Permissions (sample)")
    st.caption("Full list available in the JSON report.")
    for p in report['permissions'][:10]:
        st.markdown(f"- `{p}`")
    if len(report['permissions']) > 10:
        st.markdown("- ... (and more)")

    st.markdown("---")
    st.info("This analysis is automated and may not capture all privacy risks. Review permissions and sensitive API usage before installing unknown apps.")

    st.download_button(
        label="Download Full JSON Report",
        data=json.dumps(report, indent=2),
        file_name="privacy_risk_report.json",
        mime="application/json"
    ) 
