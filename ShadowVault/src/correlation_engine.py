"""
Operation ShadowVault - Correlation Engine
============================================
Runs every stage detector, merges the results into a single chronological
incident timeline, and produces a simple per-host risk score so an
analyst can see at a glance which assets were most heavily involved.
"""

import sys
from pathlib import Path
import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent))
from utils import load_logs
from detectors import initial_access, credential_access, lateral_movement, exfiltration, ransomware

SEVERITY_WEIGHT = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
ALERT_COLUMNS = [
    "Stage", "Technique", "MITRE_ID", "Timestamp",
    "Hostname", "Account", "Detail", "Severity",
]


def correlate_logs(sec, sysmon, fw, files):
    """Run every detector against four already-loaded telemetry frames."""
    all_alerts = []
    all_alerts += initial_access.detect(sysmon)
    all_alerts += credential_access.detect(sysmon, files)
    all_alerts += lateral_movement.detect(sec, sysmon)
    all_alerts += exfiltration.detect(sysmon, fw)
    all_alerts += ransomware.detect(sysmon, sec, files)

    if not all_alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    timeline = pd.DataFrame(all_alerts, columns=ALERT_COLUMNS)
    timeline = timeline.sort_values("Timestamp").reset_index(drop=True)
    return timeline


def run_all_detectors():
    """Load the bundled dataset and return its correlated alert timeline."""
    return correlate_logs(*load_logs())


def score_by_host(timeline):
    if timeline.empty:
        return pd.DataFrame(columns=["Hostname", "RiskScore"])
    scored = timeline.copy()
    scored["Weight"] = scored["Severity"].map(SEVERITY_WEIGHT).fillna(0)
    risk = (scored.groupby("Hostname")["Weight"].sum()
            .sort_values(ascending=False).reset_index()
            .rename(columns={"Weight": "RiskScore"}))
    return risk


def attack_chain_summary(timeline):
    if timeline.empty:
        return pd.DataFrame(columns=["Stage", "Alerts", "First_Seen", "Last_Seen"])
    return (timeline.groupby("Stage")
            .agg(Alerts=("Stage", "count"),
                 First_Seen=("Timestamp", "min"),
                 Last_Seen=("Timestamp", "max"))
            .reset_index()
            .sort_values("Stage"))


def main():
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    timeline = run_all_detectors()
    risk = score_by_host(timeline)
    summary = attack_chain_summary(timeline)

    timeline.to_csv(PROCESSED_DIR / "incident_timeline.csv", index=False)
    risk.to_csv(PROCESSED_DIR / "host_risk_scores.csv", index=False)
    summary.to_csv(PROCESSED_DIR / "attack_chain_summary.csv", index=False)

    print(f"Correlated {len(timeline)} alerts across {timeline['Stage'].nunique()} attack stages.")
    print("\n--- Attack Chain Summary ---")
    print(summary.to_string(index=False))
    print("\n--- Host Risk Scores ---")
    print(risk.to_string(index=False))
    print(f"\nWrote timeline, risk scores, and stage summary to {PROCESSED_DIR}")
    return timeline, risk, summary


if __name__ == "__main__":
    main()
