"""Shared helpers used across all ShadowVault detection modules."""

from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

LOG_SCHEMAS = {
    "windows_security_events.csv": [
        "Timestamp", "Hostname", "EventID", "EventDescription", "Account",
        "Domain", "SourceIP", "LogonType", "Status",
    ],
    "sysmon_events.csv": [
        "Timestamp", "Hostname", "EventID", "Image", "CommandLine",
        "ParentImage", "ParentCommandLine", "User", "TargetImage",
        "GrantedAccess", "DestinationIP", "DestinationPort", "Protocol",
    ],
    "network_firewall_logs.csv": [
        "Timestamp", "SourceIP", "SourcePort", "DestinationIP",
        "DestinationPort", "Protocol", "Action", "BytesSent",
        "BytesReceived", "Direction",
    ],
    "file_activity_logs.csv": [
        "Timestamp", "Hostname", "Account", "FilePath", "Action",
        "OriginalExtension", "NewExtension", "ProcessName", "FileSizeBytes",
    ],
}

ASSET_IP_MAP = {
    "10.10.12.47": "WKS-FIN-07",
    "10.10.14.22": "WKS-ENG-12",
    "10.10.16.9": "WKS-HR-03",
    "10.10.20.5": "WKS-IT-02",
    "10.10.5.10": "SRV-FILE-01",
    "10.10.5.1": "SRV-DC-01",
}


def load_logs():
    """Load all four log sources as pandas DataFrames with parsed timestamps."""
    sec = pd.read_csv(DATA_DIR / "windows_security_events.csv", parse_dates=["Timestamp"])
    sysmon = pd.read_csv(DATA_DIR / "sysmon_events.csv", parse_dates=["Timestamp"])
    fw = pd.read_csv(DATA_DIR / "network_firewall_logs.csv", parse_dates=["Timestamp"])
    files = pd.read_csv(DATA_DIR / "file_activity_logs.csv", parse_dates=["Timestamp"])
    return sec, sysmon, fw, files


def validate_log_frame(frame, filename):
    """Return the columns missing from one supported telemetry CSV."""
    expected = LOG_SCHEMAS[filename]
    return [column for column in expected if column not in frame.columns]


def normalize_log_frame(frame, filename):
    """Validate and normalize types used by the detection modules."""
    missing = validate_log_frame(frame, filename)
    if missing:
        raise ValueError(f"{filename} is missing columns: {', '.join(missing)}")

    normalized = frame.copy()
    normalized["Timestamp"] = pd.to_datetime(normalized["Timestamp"], errors="raise")
    if "EventID" in normalized:
        normalized["EventID"] = pd.to_numeric(normalized["EventID"], errors="raise").astype(int)
    for numeric_column in ("LogonType", "BytesSent", "FileSizeBytes"):
        if numeric_column in normalized:
            normalized[numeric_column] = pd.to_numeric(normalized[numeric_column], errors="coerce")
    return normalized


def resolve_hostname(ip_address):
    """Resolve a known lab IP to its asset name while preserving unknown IPs."""
    return ASSET_IP_MAP.get(str(ip_address), str(ip_address))


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
