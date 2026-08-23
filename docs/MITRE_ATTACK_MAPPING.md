# MITRE ATT&CK Mapping — Operation ShadowVault

Each stage of the simulated intrusion is mapped to the ATT&CK Enterprise
matrix so the project can be discussed in the vocabulary a SOC / threat
intel team actually uses.

| Stage | Technique | ID | Detected By |
|---|---|---|---|
| 1. Initial Access | Spearphishing Attachment | T1566.001 | `detectors/initial_access.py` |
| 1. Initial Access | User Execution: Malicious File | T1204.002 | `detectors/initial_access.py` |
| 1. Initial Access | Command and Scripting Interpreter: PowerShell | T1059.001 | `detectors/initial_access.py` |
| 2. Credential Theft | OS Credential Dumping: LSASS Memory | T1003.001 | `detectors/credential_access.py` |
| 3. Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | `detectors/lateral_movement.py` |
| 3. Lateral Movement | System Services: Service Execution | T1569.002 | `detectors/lateral_movement.py` |
| 4. Data Exfiltration Attempt | Archive Collected Data | T1560 | `detectors/exfiltration.py` |
| 4. Data Exfiltration Attempt | Exfiltration Over C2 Channel | T1041 | `detectors/exfiltration.py` |
| 5. Ransomware Deployment | Inhibit System Recovery | T1490 | `detectors/ransomware.py` |
| 5. Ransomware Deployment | Data Encrypted for Impact | T1486 | `detectors/ransomware.py` |
| 5. Ransomware Deployment | Indicator Removal: Clear Windows Event Logs | T1070.001 | `detectors/ransomware.py` |

## Why this mapping matters for the project write-up

Framing detections against ATT&CK IDs (rather than just "found something
weird") is what separates a hobby script from something that reads as
SOC-analyst work on a resume. It also makes the project directly
comparable to how real detection engineering teams document coverage —
you can point at this table and say exactly which techniques your
tooling covers, and which ones (initial delivery via email gateway,
EDR-based blocking, etc.) are out of scope for this iteration.

## Full Attack Path (Attack Flow)

```
Phishing Email (T1566.001)
        │
        ▼
Macro Executes PowerShell (T1204.002, T1059.001)
        │
        ▼
LSASS Memory Dump (T1003.001)  ──►  IT Admin credentials stolen
        │
        ▼
Lateral Movement via SMB/Service Creation (T1021.002, T1569.002)
        │
        ▼
Data Staged & Exfil Attempted (T1560, T1041)
        │
        ▼
Shadow Copies Deleted (T1490)
        │
        ▼
Mass File Encryption + Ransom Note (T1486)
```
