"""Detections for an optional Yocto/OpenEmbedded embedded Linux endpoint.

The module analyzes normalized telemetry only. It does not execute commands on
the device or perform active response.
"""

from datetime import timedelta

from utils import alert


AUTH_FAILURE_THRESHOLD = 5
AUTH_FAILURE_WINDOW = timedelta(minutes=10)
SENSITIVE_PATH_PREFIXES = (
    "/etc/audit/",
    "/etc/rsyslog.conf",
    "/etc/rsyslog.d/",
    "/etc/ssh/sshd_config",
)


def _is_sensitive_path(path):
    normalized = str(path).strip()
    return any(normalized == prefix.rstrip("/") or normalized.startswith(prefix)
               for prefix in SENSITIVE_PATH_PREFIXES)


def detect(events):
    """Return alerts for brute force, telemetry tampering, and sudo abuse."""
    if events is None or events.empty:
        return []

    alerts = []
    normalized = events.copy().sort_values("Timestamp")
    event_types = normalized["EventType"].astype(str).str.upper()
    results = normalized["Result"].astype(str).str.lower()

    failures = normalized[
        (event_types == "AUTH_FAILURE")
        & results.isin({"failure", "failed", "denied"})
    ]
    for (hostname, remote_ip), group in failures.groupby(["Hostname", "RemoteIP"]):
        group = group.sort_values("Timestamp")
        for start_index in range(len(group)):
            window_start = group.iloc[start_index]["Timestamp"]
            window_end = window_start + AUTH_FAILURE_WINDOW
            window = group[
                (group["Timestamp"] >= window_start)
                & (group["Timestamp"] <= window_end)
            ]
            if len(window) < AUTH_FAILURE_THRESHOLD:
                continue
            accounts = sorted(set(window["Account"].astype(str)))
            alerts.append(alert(
                stage="Embedded Endpoint Monitoring",
                technique="Repeated SSH authentication failures on Yocto endpoint",
                mitre_id="T1110.001",
                timestamp=window["Timestamp"].max(),
                host=hostname,
                account=", ".join(accounts),
                detail=(
                    f"{len(window)} failures from {remote_ip} within "
                    f"{int(AUTH_FAILURE_WINDOW.total_seconds() / 60)} minutes"
                ),
                severity="High",
            ))
            break

    config_changes = normalized[
        (event_types == "CONFIG_CHANGE")
        & normalized["Path"].apply(_is_sensitive_path)
    ]
    for _, row in config_changes.iterrows():
        alerts.append(alert(
            stage="Embedded Endpoint Monitoring",
            technique="Security telemetry configuration modified",
            mitre_id="T1562.001",
            timestamp=row["Timestamp"],
            host=row["Hostname"],
            account=row["Account"],
            detail=f"{row['Path']} :: {row['Message']}",
            severity="Critical",
        ))

    privileged = normalized[
        (event_types == "PRIVILEGED_EXEC")
        & ~normalized["Account"].astype(str).str.lower().isin({"", "0", "root", "nan"})
    ]
    for _, row in privileged.iterrows():
        alerts.append(alert(
            stage="Embedded Endpoint Monitoring",
            technique="Non-root account executed a privileged command",
            mitre_id="T1548.003",
            timestamp=row["Timestamp"],
            host=row["Hostname"],
            account=row["Account"],
            detail=f"{row['Path']} :: {row['Message']}",
            severity="High",
        ))

    return alerts
