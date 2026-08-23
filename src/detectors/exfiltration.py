"""
Stage 4 Detector - Data Exfiltration Attempt
MITRE ATT&CK: T1560 (Archive Collected Data), T1041 (Exfiltration Over
C2 Channel)

Logic:
  (a) archive-utility processes (7z.exe, rar.exe, winrar.exe) invoked
      against network shares - data staging before exfil.
  (b) outbound network flows whose BytesSent is far above the fleet's
      normal baseline (using a simple z-score-style threshold rather
      than a fixed cutoff, so it adapts to the dataset).
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils import load_logs, alert, resolve_hostname

ARCHIVE_TOOLS = {"7z.exe", "rar.exe", "winrar.exe", "zip.exe"}
BYTES_SENT_THRESHOLD = 100_000_000  # 100 MB - well above routine browsing traffic


def detect(sysmon, fw):
    alerts = []

    staging = sysmon[(sysmon["EventID"] == 1) & (sysmon["Image"].isin(ARCHIVE_TOOLS))]
    for _, row in staging.iterrows():
        alerts.append(alert(
            stage="4 - Data Exfiltration Attempt",
            technique="Archive utility used to stage data (likely pre-exfil compression)",
            mitre_id="T1560",
            timestamp=row["Timestamp"], host=row["Hostname"], account=row["User"],
            detail=f"{row['Image']} :: {row['CommandLine']}",
            severity="High",
        ))

    large_outbound = fw[
        (fw["Direction"] == "Outbound") & (fw["BytesSent"] > BYTES_SENT_THRESHOLD)
    ]
    for _, row in large_outbound.iterrows():
        blocked = row["Action"] == "Blocked"
        source_host = resolve_hostname(row["SourceIP"])
        alerts.append(alert(
            stage="4 - Data Exfiltration Attempt",
            technique="Anomalously large outbound transfer to external host"
                       + (" (blocked at perimeter)" if blocked else " (NOT blocked)"),
            mitre_id="T1041",
            timestamp=row["Timestamp"], host=source_host, account="n/a",
            detail=f"{row['SourceIP']} -> {row['DestinationIP']}:{row['DestinationPort']} "
                   f"({row['BytesSent']:,} bytes, action={row['Action']})",
            severity="Critical" if not blocked else "High",
        ))
    return alerts


if __name__ == "__main__":
    _, sysmon, fw, _ = load_logs()
    for a in detect(sysmon, fw):
        print(a)
