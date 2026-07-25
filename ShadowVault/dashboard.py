"""Interactive SOC investigation dashboard for Operation ShadowVault."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


PROJECT_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = PROJECT_DIR / "data" / "processed"

st.set_page_config(page_title="ShadowVault SOC Dashboard", page_icon="🛡️", layout="wide")


@st.cache_data
def load_results():
    """Load outputs produced by the correlation engine."""
    timeline_path = PROCESSED_DIR / "incident_timeline.csv"
    risk_path = PROCESSED_DIR / "host_risk_scores.csv"
    summary_path = PROCESSED_DIR / "attack_chain_summary.csv"

    missing = [path.name for path in (timeline_path, risk_path, summary_path) if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing generated data: " + ", ".join(missing)
            + ". Run the generator and correlation engine first."
        )

    timeline = pd.read_csv(timeline_path, parse_dates=["Timestamp"])
    risk = pd.read_csv(risk_path)
    summary = pd.read_csv(summary_path, parse_dates=["First_Seen", "Last_Seen"])
    return timeline, risk, summary


st.title("🛡️ Operation ShadowVault")
st.caption("SOC investigation dashboard for the simulated ransomware incident")

try:
    timeline, risk, summary = load_results()
except FileNotFoundError as error:
    st.error(str(error))
    st.code("py src/log_generator.py\npy src/correlation_engine.py", language="powershell")
    st.stop()

st.sidebar.header("Investigation filters")
stages = st.sidebar.multiselect("Attack stage", sorted(timeline["Stage"].unique()), default=sorted(timeline["Stage"].unique()))
severities = st.sidebar.multiselect("Severity", sorted(timeline["Severity"].unique()), default=sorted(timeline["Severity"].unique()))
hosts = st.sidebar.multiselect("Hostname", sorted(timeline["Hostname"].unique()), default=sorted(timeline["Hostname"].unique()))

filtered = timeline[
    timeline["Stage"].isin(stages)
    & timeline["Severity"].isin(severities)
    & timeline["Hostname"].isin(hosts)
].copy()

critical_alerts = int((filtered["Severity"] == "Critical").sum())
first_seen = filtered["Timestamp"].min() if not filtered.empty else None

metric_one, metric_two, metric_three, metric_four = st.columns(4)
metric_one.metric("Alerts", len(filtered))
metric_two.metric("Critical alerts", critical_alerts)
metric_three.metric("Affected hosts", filtered["Hostname"].nunique())
metric_four.metric("First activity", first_seen.strftime("%H:%M:%S") if first_seen else "—")

left, right = st.columns((3, 2))
with left:
    st.subheader("Attack timeline")
    if filtered.empty:
        st.info("No alerts match the selected filters.")
    else:
        fig = px.scatter(
            filtered,
            x="Timestamp",
            y="Stage",
            color="Severity",
            symbol="Hostname",
            hover_data=["Hostname", "Account", "MITRE_ID", "Technique", "Detail"],
            category_orders={"Severity": ["Critical", "High", "Medium", "Low"]},
            color_discrete_map={"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#2563eb"},
        )
        fig.update_layout(height=410, legend_title_text="")
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Host risk scores")
    risk_chart = px.bar(
        risk.sort_values("RiskScore"),
        x="RiskScore",
        y="Hostname",
        orientation="h",
        color="RiskScore",
        color_continuous_scale="Reds",
    )
    risk_chart.update_layout(height=410, coloraxis_showscale=False)
    st.plotly_chart(risk_chart, use_container_width=True)

st.subheader("Attack-chain coverage")
coverage = summary.copy()
coverage["Stage"] = coverage["Stage"].str.replace(r"^\d+\s+-\s+", "", regex=True)
st.bar_chart(coverage.set_index("Stage")["Alerts"], color="#ef4444")

st.subheader("Alert evidence")
st.dataframe(
    filtered.sort_values("Timestamp"),
    use_container_width=True,
    hide_index=True,
    column_config={
        "Timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
        "Detail": st.column_config.TextColumn("Evidence", width="large"),
    },
)

st.download_button(
    "Download filtered alerts (CSV)",
    filtered.to_csv(index=False).encode("utf-8"),
    file_name="shadowvault_filtered_alerts.csv",
    mime="text/csv",
)
