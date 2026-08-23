"""
Stage 5 Detector - Ransomware Deployment
MITRE ATT&CK: T1490 (Inhibit System Recovery), T1486 (Data Encrypted
for Impact), T1070.001 (Clear Windows Event Logs - anti-forensics)

Logic:
  (a) vssadmin/wmic invoked to delete shadow copies - almost never
      legitimate outside of scripted backup maintenance.
  (b) a burst of file rename events on a host that all convert to the
      *same* unfamiliar extension within a short window - the
      signature of mass encryption.
  (c) ransom-note-style filenames being created.
  (d) security event log clearing immediately around the same time.
"""

import sys
from pathlib import Path
from collections import Counter
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils import load_logs, alert

KNOWN_EXTENSIONS = {"xlsx", "docx", "csv", "pptx", "pdf", "dwg", "txt", "7z", "tmp", "exe", "docm"}
RANSOM_NOTE_HINTS = ["recover", "readme", "decrypt", "restore", "how_to"]
RENAME_BURST_THRESHOLD = 3


def detect(sysmon, sec, files):
    alerts = []

    shadow_deletes = sysmon[
        (sysmon["EventID"] == 1)
        & (sysmon["Image"].isin(["vssadmin.exe", "wmic.exe"]))
        & (sysmon["CommandLine"].astype(str).str.contains("shadow", case=False, na=False))
    ]
    for _, row in shadow_deletes.iterrows():
        alerts.append(alert(
            stage="5 - Ransomware Deployment",
            technique="Volume shadow copies deleted (backup/recovery sabotage)",
            mitre_id="T1490",
            timestamp=row["Timestamp"], host=row["Hostname"], account=row["User"],
            detail=row["CommandLine"], severity="Critical",
        ))

    cleared_logs = sec[sec["EventID"] == 1102]
    for _, row in cleared_logs.iterrows():
        alerts.append(alert(
            stage="5 - Ransomware Deployment",
            technique="Security audit log cleared (anti-forensics)",
            mitre_id="T1070.001",
            timestamp=row["Timestamp"], host=row["Hostname"], account=row["Account"],
            detail="1102 event log clear", severity="High",
        ))

    renames = files[(files["Action"] == "Renamed") & (~files["NewExtension"].isna())]
    for (host, ext), group in renames.groupby(["Hostname", "NewExtension"]):
        if ext.lower() in KNOWN_EXTENSIONS:
            continue
        if len(group) >= RENAME_BURST_THRESHOLD:
            span = (group["Timestamp"].max() - group["Timestamp"].min()).total_seconds()
            alerts.append(alert(
                stage="5 - Ransomware Deployment",
                technique="Mass file rename to a single unfamiliar extension "
                           "(consistent with encryption)",
                mitre_id="T1486",
                timestamp=group["Timestamp"].min(), host=host,
                account=group["Account"].iloc[0],
                detail=f"{len(group)} files renamed to *.{ext} within {span:.0f}s "
                       f"(process: {group['ProcessName'].iloc[0]})",
                severity="Critical",
            ))

    notes = files[files["FilePath"].astype(str).str.lower().apply(
        lambda p: any(h in p for h in RANSOM_NOTE_HINTS))]
    for _, row in notes.iterrows():
        alerts.append(alert(
            stage="5 - Ransomware Deployment",
            technique="Ransom note file created",
            mitre_id="T1486",
            timestamp=row["Timestamp"], host=row["Hostname"], account=row["Account"],
            detail=row["FilePath"], severity="Critical",
        ))
    return alerts


if __name__ == "__main__":
    sec, sysmon, _, files = load_logs()
    for a in detect(sysmon, sec, files):
        print(a)
