"""
Stage 1 Detector - Initial Access
MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1204.002 (User
Execution: Malicious File), T1059.001 (PowerShell)

Logic: flag any case where a document/Office process (WINWORD.EXE,
EXCEL.EXE, OUTLOOK.EXE) is the direct parent of a shell or scripting
process (powershell.exe, cmd.exe, wscript.exe) - especially with
hidden-window or encoded-command flags. This is one of the highest
fidelity phishing-execution signatures in an EDR dataset.
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils import load_logs, alert

OFFICE_PARENTS = {"WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "POWERPNT.EXE"}
SUSPICIOUS_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"}
SUSPICIOUS_FLAGS = ["-enc", "-nop", "-w hidden", "-windowstyle hidden"]


def detect(sysmon):
    alerts = []
    candidates = sysmon[
        (sysmon["EventID"] == 1)
        & (sysmon["ParentImage"].isin(OFFICE_PARENTS))
        & (sysmon["Image"].isin(SUSPICIOUS_CHILDREN))
    ]

    for _, row in candidates.iterrows():
        cmdline = str(row.get("CommandLine", ""))
        flagged = any(f in cmdline for f in SUSPICIOUS_FLAGS)
        severity = "Critical" if flagged else "High"
        alerts.append(alert(
            stage="1 - Initial Access",
            technique="Office application spawned scripting engine"
                       + (" with obfuscation flags" if flagged else ""),
            mitre_id="T1566.001 / T1204.002 / T1059.001",
            timestamp=row["Timestamp"], host=row["Hostname"],
            account=row.get("User", "unknown"),
            detail=f"{row['ParentImage']} -> {row['Image']} :: {cmdline}",
            severity=severity,
        ))
    return alerts


if __name__ == "__main__":
    _, sysmon, _, _ = load_logs()
    for a in detect(sysmon):
        print(a)
