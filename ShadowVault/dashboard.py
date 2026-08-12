"""Interactive SOC investigation dashboard for Operation ShadowVault."""

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


PROJECT_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = PROJECT_DIR / "data" / "processed"
sys.path.insert(0, str(PROJECT_DIR / "src"))

from correlation_engine import attack_chain_summary, correlate_logs, score_by_host
from report_generator import build_report, build_uploaded_report
from utils import LOG_SCHEMAS, normalize_log_frame


st.set_page_config(page_title="ShadowVault SOC Dashboard", page_icon="🛡️", layout="wide")


@st.cache_data
def load_sample_results():
    """Load outputs produced by the bundled simulation pipeline."""
    timeline_path = PROCESSED_DIR / "incident_timeline.csv"
    risk_path = PROCESSED_DIR / "host_risk_scores.csv"
    summary_path = PROCESSED_DIR / "attack_chain_summary.csv"
    metrics_path = PROCESSED_DIR / "evaluation_metrics.json"

    missing = [path.name for path in (timeline_path, risk_path, summary_path) if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing generated data: " + ", ".join(missing)
            + ". Run python run_pipeline.py first."
        )

    timeline = pd.read_csv(timeline_path, parse_dates=["Timestamp"])
    risk = pd.read_csv(risk_path)
    summary = pd.read_csv(summary_path, parse_dates=["First_Seen", "Last_Seen"])
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    return timeline, risk, summary, metrics


def read_uploaded_logs(uploaded_files):
    """Read, validate, and normalize four uploaded CSVs without saving them."""
    frames = {}
    for filename, uploaded_file in uploaded_files.items():
        try:
            frame = pd.read_csv(uploaded_file)
            frames[filename] = normalize_log_frame(frame, filename)
        except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"{filename}: {error}") from error
    return frames


st.title("🛡️ Operation ShadowVault")
st.caption("SOC investigation dashboard for sample or recruiter-supplied telemetry")

st.sidebar.header("Data source")
data_mode = st.sidebar.radio(
    "Choose investigation data",
    ["Built-in simulation", "Upload my CSV logs"],
    help="Uploaded files are processed in memory and do not replace the bundled dataset.",
)

if data_mode == "Built-in simulation":
    try:
        timeline, risk, summary, metrics = load_sample_results()
    except FileNotFoundError as error:
        st.error(str(error))
        st.code("python run_pipeline.py", language="powershell")
        st.stop()
    report_name = "shadowvault_sample_incident_report.md"
else:
    st.info(
        "Upload all four CSV telemetry sources. Files are processed only for this dashboard "
        "session and are not written over the sample dataset. Remove confidential or personal "
        "information before using logs outside an authorized environment."
    )

    with st.expander("Required filenames and columns"):
        for filename, columns in LOG_SCHEMAS.items():
            st.markdown(f"**{filename}**")
            st.code(",".join(columns), language="text")

    upload_left, upload_right = st.columns(2)
    with upload_left:
        security_upload = st.file_uploader(
            "Windows Security events",
            type="csv",
            key="security_upload",
            help="Expected structure: windows_security_events.csv",
        )
        sysmon_upload = st.file_uploader(
            "Sysmon events",
            type="csv",
            key="sysmon_upload",
            help="Expected structure: sysmon_events.csv",
        )
    with upload_right:
        firewall_upload = st.file_uploader(
            "Network firewall logs",
            type="csv",
            key="firewall_upload",
            help="Expected structure: network_firewall_logs.csv",
        )
        file_activity_upload = st.file_uploader(
            "File activity logs",
            type="csv",
            key="file_activity_upload",
            help="Expected structure: file_activity_logs.csv",
        )

    uploaded_files = {
        "windows_security_events.csv": security_upload,
        "sysmon_events.csv": sysmon_upload,
        "network_firewall_logs.csv": firewall_upload,
        "file_activity_logs.csv": file_activity_upload,
    }
    missing_uploads = [filename for filename, file in uploaded_files.items() if file is None]
    if missing_uploads:
        st.warning("Upload all four CSV files to begin the investigation.")
        st.stop()

    try:
        frames = read_uploaded_logs(uploaded_files)
        timeline = correlate_logs(
            frames["windows_security_events.csv"],
            frames["sysmon_events.csv"],
            frames["network_firewall_logs.csv"],
            frames["file_activity_logs.csv"],
        )
    except ValueError as error:
        st.error(f"CSV validation failed: {error}")
        st.stop()

    risk = score_by_host(timeline)
    summary = attack_chain_summary(timeline)
    metrics = {}
    report_name = "shadowvault_uploaded_logs_incident_report.md"
    st.success(
        f"Validated and processed {sum(len(frame) for frame in frames.values()):,} log rows. "
        f"Generated {len(timeline)} alerts."
    )
    if timeline.empty:
        st.warning(
            "No included ShadowVault detection rules matched these files. This does not prove "
            "the environment is clean; it only describes the coverage of the current rules."
        )


st.sidebar.header("Investigation filters")
stage_options = sorted(timeline["Stage"].dropna().unique())
severity_options = sorted(timeline["Severity"].dropna().unique())
host_options = sorted(timeline["Hostname"].dropna().unique())
stages = st.sidebar.multiselect("Attack stage", stage_options, default=stage_options)
severities = st.sidebar.multiselect("Severity", severity_options, default=severity_options)
hosts = st.sidebar.multiselect("Hostname", host_options, default=host_options)

filtered = timeline[
    timeline["Stage"].isin(stages)
    & timeline["Severity"].isin(severities)
    & timeline["Hostname"].isin(hosts)
].copy()

critical_alerts = int((filtered["Severity"] == "Critical").sum())
first_seen = filtered["Timestamp"].min() if not filtered.empty else None
benchmark_f1 = metrics.get("f1_score")

metric_one, metric_two, metric_three, metric_four, metric_five = st.columns(5)
metric_one.metric("Alerts", len(filtered))
metric_two.metric("Critical alerts", critical_alerts)
metric_three.metric("Affected assets", filtered["Hostname"].nunique())
metric_four.metric("First activity", first_seen.strftime("%H:%M:%S") if first_seen else "—")
metric_five.metric(
    "Synthetic F1" if benchmark_f1 is not None else "Data mode",
    f"{benchmark_f1:.2f}" if benchmark_f1 is not None else "Uploaded",
)

if metrics:
    st.caption(metrics.get("scope_note", ""))
elif data_mode == "Upload my CSV logs":
    st.caption("Ground-truth benchmark metrics are intentionally disabled for uploaded logs.")

left, right = st.columns((3, 2))
with left:
    st.subheader("Attack timeline")
    if filtered.empty:
        st.info("No alerts match the selected filters.")
    else:
        figure = px.scatter(
            filtered,
            x="Timestamp",
            y="Stage",
            color="Severity",
            symbol="Hostname",
            hover_data=["Hostname", "Account", "MITRE_ID", "Technique", "Detail"],
            category_orders={"Severity": ["Critical", "High", "Medium", "Low"]},
            color_discrete_map={
                "Critical": "#dc2626", "High": "#f97316",
                "Medium": "#eab308", "Low": "#2563eb",
            },
        )
        figure.update_layout(height=410, legend_title_text="")
        st.plotly_chart(figure, use_container_width=True)

with right:
    st.subheader("Asset risk scores")
    if risk.empty:
        st.info("No scored assets are available.")
    else:
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
if summary.empty:
    st.info("No attack-stage coverage is available.")
else:
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

download_left, download_right = st.columns(2)
with download_left:
    st.download_button(
        "Download filtered alerts (CSV)",
        filtered.to_csv(index=False).encode("utf-8"),
        file_name="shadowvault_filtered_alerts.csv",
        mime="text/csv",
    )

with download_right:
    if not timeline.empty:
        report_text = (
            build_report(timeline, risk, summary)
            if data_mode == "Built-in simulation"
            else build_uploaded_report(timeline, risk, summary)
        )
        st.download_button(
            "Download incident report (Markdown)",
            report_text.encode("utf-8"),
            file_name=report_name,
            mime="text/markdown",
        )
