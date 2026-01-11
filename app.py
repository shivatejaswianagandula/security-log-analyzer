import os
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Security Log Analyzer", layout="wide")

st.title("Security Log Analyzer Dashboard")
st.caption("Visualize failed login attempts and suspicious IP activity from generated CSV reports.")

st.sidebar.header("Report Paths")
report_path = st.sidebar.text_input("User+IP report", "output/report.csv")
ip_report_path = st.sidebar.text_input("IP suspicious report", "output/ip_suspicious.csv")

st.sidebar.header("How to generate reports")
st.sidebar.code("python3 src/analyze.py --threshold 2 --ip-user-threshold 2", language="bash")

def load_csv(path: str):
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)

col1, col2 = st.columns(2)

with col1:
    st.subheader("User + IP Failed Login Report")
    df1 = load_csv(report_path)
    if df1 is None:
        st.warning(f"File not found: {report_path}")
    else:
        st.dataframe(df1, use_container_width=True)
        suspicious1 = df1[df1["Suspicious"] == "YES"]
        st.markdown("**Suspicious rows**")
        st.dataframe(suspicious1, use_container_width=True)

with col2:
    st.subheader("IP Multi-User Attack Report")
    df2 = load_csv(ip_report_path)
    if df2 is None:
        st.warning(f"File not found: {ip_report_path}")
    else:
        st.dataframe(df2, use_container_width=True)
        suspicious2 = df2[df2["Suspicious"] == "YES"]
        st.markdown("**Suspicious IPs**")
        st.dataframe(suspicious2, use_container_width=True)

st.divider()
st.subheader("Quick Summary")

if df1 is not None:
    st.write("Total (user,ip) rows:", len(df1))
    st.write("Suspicious (user,ip) rows:", int((df1["Suspicious"] == "YES").sum()))

if df2 is not None:
    st.write("Total IP rows:", len(df2))
    st.write("Suspicious IP rows:", int((df2["Suspicious"] == "YES").sum()))
