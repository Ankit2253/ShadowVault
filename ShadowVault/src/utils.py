"""Shared helpers used across all ShadowVault detection modules."""

from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"


def load_logs():
    """Load all four log sources as pandas DataFrames with parsed timestamps."""
    sec = pd.read_csv(DATA_DIR / "windows_security_events.csv", parse_dates=["Timestamp"])
    sysmon = pd.read_csv(DATA_DIR / "sysmon_events.csv", parse_dates=["Timestamp"])
    fw = pd.read_csv(DATA_DIR / "network_firewall_logs.csv", parse_dates=["Timestamp"])
    files = pd.read_csv(DATA_DIR / "file_activity_logs.csv", parse_dates=["Timestamp"])
    return sec, sysmon, fw, files


def alert(stage, technique, mitre_id, timestamp, host, account, detail, severity="High"):
    """Build a standardized alert record so every detector returns the same shape."""
    return {
        "Stage": stage,
        "Technique": technique,
        "MITRE_ID": mitre_id,
        "Timestamp": timestamp,
        "Hostname": host,
        "Account": account,
        "Detail": detail,
        "Severity": severity,
    }
