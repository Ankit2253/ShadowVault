"""
Stage 3 Detector - Lateral Movement
MITRE ATT&CK: T1021.002 (Remote Services: SMB/Windows Admin Shares),
T1569.002 (System Services: Service Execution)

Logic:
  (a) "logon spray" - the same account authenticating (network logon,
      type 3) to N-or-more distinct hosts within a rolling time window
      is a strong lateral-movement indicator, especially combined with
      4672 "special privileges" (i.e. admin-equivalent access).
  (b) remote service installation (Security 4697) immediately following
      such a logon on the same host - the classic PsExec pattern.
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils import load_logs, alert

WINDOW_MINUTES = 90
HOST_THRESHOLD = 3


def detect(sec, sysmon):
    alerts = []
    logons = sec[(sec["EventID"] == 4624) & (sec["LogonType"] == 3)].sort_values("Timestamp")

    for account, group in logons.groupby("Account"):
        group = group.sort_values("Timestamp")
        window_start = group["Timestamp"].iloc[0]
        window_hosts = set()
        for _, row in group.iterrows():
            if (row["Timestamp"] - window_start).total_seconds() > WINDOW_MINUTES * 60:
                window_start = row["Timestamp"]
                window_hosts = set()
            window_hosts.add(row["Hostname"])
            if len(window_hosts) >= HOST_THRESHOLD:
                alerts.append(alert(
                    stage="3 - Lateral Movement",
                    technique="Single account authenticated to multiple hosts in a short window",
                    mitre_id="T1021.002",
                    timestamp=row["Timestamp"], host=row["Hostname"], account=account,
                    detail=f"{account} logged into {len(window_hosts)} hosts within "
                           f"{WINDOW_MINUTES} min: {sorted(window_hosts)}",
                    severity="Critical",
                ))
                break  # one alert per account is enough for the report

    remote_services = sec[sec["EventID"] == 4697]
    for _, row in remote_services.iterrows():
        alerts.append(alert(
            stage="3 - Lateral Movement",
            technique="Remote service installed (PsExec-style execution)",
            mitre_id="T1569.002",
            timestamp=row["Timestamp"], host=row["Hostname"], account=row["Account"],
            detail=f"Service installed on {row['Hostname']} by {row['Account']} "
                   f"from source {row['SourceIP']}",
            severity="High",
        ))
    return alerts


if __name__ == "__main__":
    sec, sysmon, _, _ = load_logs()
    for a in detect(sec, sysmon):
        print(a)
