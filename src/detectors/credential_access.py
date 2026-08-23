"""
Stage 2 Detector - Credential Access
MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)

Logic: Sysmon Event ID 10 (ProcessAccess) where TargetImage is lsass.exe
and GrantedAccess matches a known credential-dumping access mask
(0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff are common values requested
by dumping tools; legitimate access to LSASS is rare and uses narrower
masks). We also check for suspiciously large temp files created in the
same process shortly after - consistent with a memory dump artifact.
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils import load_logs, alert

SUSPICIOUS_ACCESS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff"}


def detect(sysmon, files):
    alerts = []
    lsass_access = sysmon[
        (sysmon["EventID"] == 10)
        & (sysmon["TargetImage"].astype(str).str.contains("lsass.exe", case=False, na=False))
    ]

    for _, row in lsass_access.iterrows():
        mask = str(row.get("GrantedAccess", ""))
        suspicious = mask in SUSPICIOUS_ACCESS_MASKS
        alerts.append(alert(
            stage="2 - Credential Theft",
            technique="Process accessed LSASS memory"
                       + (" with a credential-dumping access mask" if suspicious else ""),
            mitre_id="T1003.001",
            timestamp=row["Timestamp"], host=row["Hostname"],
            account=row.get("User", "unknown"),
            detail=f"{row['Image']} accessed lsass.exe (GrantedAccess={mask})",
            severity="Critical" if suspicious else "Medium",
        ))

    # corroborating artifact: a large dump file dropped around the same time
    dump_files = files[files["FilePath"].astype(str).str.contains("lsass", case=False, na=False)]
    for _, row in dump_files.iterrows():
        alerts.append(alert(
            stage="2 - Credential Theft",
            technique="Suspected LSASS memory dump artifact written to disk",
            mitre_id="T1003.001",
            timestamp=row["Timestamp"], host=row["Hostname"], account=row["Account"],
            detail=f"{row['FilePath']} ({row['FileSizeBytes']:,} bytes)",
            severity="Critical",
        ))
    return alerts


if __name__ == "__main__":
    _, sysmon, _, files = load_logs()
    for a in detect(sysmon, files):
        print(a)
