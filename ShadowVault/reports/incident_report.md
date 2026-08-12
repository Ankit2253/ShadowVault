# Incident Report: Operation ShadowVault
**Generated:** 2026-08-13 00:44  
**Classification:** Simulated Incident (Training Exercise)  
**Organization:** Meridian Precision Manufacturing (fictional)  
**Incident Date:** 2026-07-14  
**Case Status:** Contained; recovery and credential reset required

## Executive Summary
On 2026-07-14, an employee in Accounts Payable opened a malicious attachment delivered via email, triggering a five-stage intrusion that progressed from initial access to full ransomware deployment in approximately **5.2 hours**. The attacker dumped credentials from a compromised finance workstation, used a stolen IT administrator account to move laterally across the environment, staged and attempted to exfiltrate proprietary data to external infrastructure, and ultimately deployed ransomware that deleted shadow copy backups and encrypted files across three workstations and the file server. This report reconstructs the full attack chain from correlated log data. Alert evidence was observed on **5 named assets**.

## Scope and Confidence
This report is produced from a deterministic, labelled training dataset. The detections provide high-confidence evidence for this scenario, but the benchmark results must not be interpreted as production detection performance.

## Attack Chain Overview
| Stage | Alerts | First Observed | Last Observed |
|---|---|---|---|
| 1 - Initial Access | 1 | 2026-07-14 09:16:12 | 2026-07-14 09:16:12 |
| 2 - Credential Theft | 2 | 2026-07-14 09:45:09 | 2026-07-14 09:45:20 |
| 3 - Lateral Movement | 5 | 2026-07-14 10:30:20 | 2026-07-14 11:07:43 |
| 4 - Data Exfiltration Attempt | 3 | 2026-07-14 12:31:00 | 2026-07-14 12:51:30 |
| 5 - Ransomware Deployment | 16 | 2026-07-14 14:00:39 | 2026-07-14 14:30:45 |

## Host Risk Ranking
| Host | Risk Score |
|---|---|
| SRV-FILE-01 | 23 |
| WKS-FIN-07 | 20 |
| WKS-ENG-12 | 13 |
| WKS-HR-03 | 13 |
| SRV-DC-01 | 2 |

## Detailed Timeline

### 1 - Initial Access
- **2026-07-14 09:16:12** 🔴 `T1566.001 / T1204.002 / T1059.001` — Office application spawned scripting engine with obfuscation flags on **WKS-FIN-07** (account: s.jenkins)  
  _WINWORD.EXE -> powershell.exe :: powershell.exe -nop -w hidden -enc <base64-encoded-command>_

### 2 - Credential Theft
- **2026-07-14 09:45:09** 🔴 `T1003.001` — Process accessed LSASS memory with a credential-dumping access mask on **WKS-FIN-07** (account: s.jenkins)  
  _svchost_upd.exe accessed lsass.exe (GrantedAccess=0x1010)_
- **2026-07-14 09:45:20** 🔴 `T1003.001` — Suspected LSASS memory dump artifact written to disk on **WKS-FIN-07** (account: s.jenkins)  
  _C:\Users\s.jenkins\AppData\Local\Temp\lsass_dump.tmp (61,204,112 bytes)_

### 3 - Lateral Movement
- **2026-07-14 10:30:20** 🟠 `T1569.002` — Remote service installed (PsExec-style execution) on **WKS-ENG-12** (account: j.alvarez)  
  _Service installed on WKS-ENG-12 by j.alvarez from source 10.10.12.47_
- **2026-07-14 10:45:28** 🟠 `T1569.002` — Remote service installed (PsExec-style execution) on **WKS-HR-03** (account: j.alvarez)  
  _Service installed on WKS-HR-03 by j.alvarez from source 10.10.12.47_
- **2026-07-14 10:55:34** 🔴 `T1021.002` — Single account authenticated to multiple hosts in a short window on **SRV-FILE-01** (account: j.alvarez)  
  _j.alvarez logged into 3 hosts within 90 min: ['SRV-FILE-01', 'WKS-ENG-12', 'WKS-HR-03']_
- **2026-07-14 10:55:43** 🟠 `T1569.002` — Remote service installed (PsExec-style execution) on **SRV-FILE-01** (account: j.alvarez)  
  _Service installed on SRV-FILE-01 by j.alvarez from source 10.10.12.47_
- **2026-07-14 11:07:43** 🟠 `T1569.002` — Remote service installed (PsExec-style execution) on **SRV-DC-01** (account: j.alvarez)  
  _Service installed on SRV-DC-01 by j.alvarez from source 10.10.12.47_

### 4 - Data Exfiltration Attempt
- **2026-07-14 12:31:00** 🟠 `T1560` — Archive utility used to stage data (likely pre-exfil compression) on **SRV-FILE-01** (account: j.alvarez)  
  _7z.exe :: 7z.exe a -mx1 archive_backup.7z "\\SRV-FILE-01\Shared\*"_
- **2026-07-14 12:44:00** 🔴 `T1041` — Anomalously large outbound transfer to external host (NOT blocked) on **SRV-FILE-01** (account: n/a)  
  _10.10.5.10 -> 203.0.113.77:443 (1,800,000,000 bytes, action=Allow)_
- **2026-07-14 12:51:30** 🟠 `T1041` — Anomalously large outbound transfer to external host (blocked at perimeter) on **SRV-FILE-01** (account: n/a)  
  _10.10.5.10 -> 203.0.113.77:443 (210,000,000 bytes, action=Blocked)_

### 5 - Ransomware Deployment
- **2026-07-14 14:00:39** 🔴 `T1490` — Volume shadow copies deleted (backup/recovery sabotage) on **WKS-ENG-12** (account: j.alvarez)  
  _vssadmin.exe delete shadows /all /quiet_
- **2026-07-14 14:00:39** 🟠 `T1070.001` — Security audit log cleared (anti-forensics) on **WKS-ENG-12** (account: j.alvarez)  
  _1102 event log clear_
- **2026-07-14 14:00:54** 🔴 `T1490` — Volume shadow copies deleted (backup/recovery sabotage) on **SRV-FILE-01** (account: j.alvarez)  
  _vssadmin.exe delete shadows /all /quiet_
- **2026-07-14 14:00:54** 🟠 `T1070.001` — Security audit log cleared (anti-forensics) on **SRV-FILE-01** (account: j.alvarez)  
  _1102 event log clear_
- **2026-07-14 14:02:43** 🟠 `T1070.001` — Security audit log cleared (anti-forensics) on **WKS-FIN-07** (account: j.alvarez)  
  _1102 event log clear_
- **2026-07-14 14:02:43** 🔴 `T1490` — Volume shadow copies deleted (backup/recovery sabotage) on **WKS-FIN-07** (account: j.alvarez)  
  _vssadmin.exe delete shadows /all /quiet_
- **2026-07-14 14:03:21** 🟠 `T1070.001` — Security audit log cleared (anti-forensics) on **WKS-HR-03** (account: j.alvarez)  
  _1102 event log clear_
- **2026-07-14 14:03:21** 🔴 `T1490` — Volume shadow copies deleted (backup/recovery sabotage) on **WKS-HR-03** (account: j.alvarez)  
  _vssadmin.exe delete shadows /all /quiet_
- **2026-07-14 14:14:00** 🔴 `T1486` — Mass file rename to a single unfamiliar extension (consistent with encryption) on **WKS-ENG-12** (account: j.alvarez)  
  _4 files renamed to *.shadowvault within 21s (process: encryptor.exe)_
- **2026-07-14 14:14:45** 🔴 `T1486` — Ransom note file created on **WKS-ENG-12** (account: j.alvarez)  
  _C:\Users\Shared\!!!RECOVER_YOUR_FILES!!!.txt_
- **2026-07-14 14:16:00** 🔴 `T1486` — Mass file rename to a single unfamiliar extension (consistent with encryption) on **WKS-HR-03** (account: j.alvarez)  
  _4 files renamed to *.shadowvault within 21s (process: encryptor.exe)_
- **2026-07-14 14:16:45** 🔴 `T1486` — Ransom note file created on **WKS-HR-03** (account: j.alvarez)  
  _C:\Users\Shared\!!!RECOVER_YOUR_FILES!!!.txt_
- **2026-07-14 14:26:00** 🔴 `T1486` — Mass file rename to a single unfamiliar extension (consistent with encryption) on **SRV-FILE-01** (account: j.alvarez)  
  _4 files renamed to *.shadowvault within 21s (process: encryptor.exe)_
- **2026-07-14 14:26:45** 🔴 `T1486` — Ransom note file created on **SRV-FILE-01** (account: j.alvarez)  
  _C:\Users\Shared\!!!RECOVER_YOUR_FILES!!!.txt_
- **2026-07-14 14:30:00** 🔴 `T1486` — Mass file rename to a single unfamiliar extension (consistent with encryption) on **WKS-FIN-07** (account: j.alvarez)  
  _4 files renamed to *.shadowvault within 21s (process: encryptor.exe)_
- **2026-07-14 14:30:45** 🔴 `T1486` — Ransom note file created on **WKS-FIN-07** (account: j.alvarez)  
  _C:\Users\Shared\!!!RECOVER_YOUR_FILES!!!.txt_

## Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| External IP (stager) | 203.0.113.55 |
| External IP (exfil destination) | 203.0.113.77 |
| File | Invoice_84421.docm |
| File | svchost_upd.exe |
| File | encryptor.exe |
| File extension | *.shadowvault |
| File | !!!RECOVER_YOUR_FILES!!!.txt |
| Compromised account | j.alvarez (IT admin, credentials stolen) |

## Recommendations
- Enforce macro execution restrictions (block macros from internet-sourced Office files) to close the initial access vector.
- Deploy LSASS access protections (Credential Guard / PPL) to prevent memory dumping.
- Restrict and monitor use of administrative accounts for interactive/network logons across multiple hosts.
- Alert on `vssadmin delete shadows` and similar shadow-copy deletion commands.
- Implement DLP egress filtering and alerting on large outbound transfers to unfamiliar external hosts.
- Maintain offline/immutable backups so shadow-copy deletion cannot prevent recovery.

## Incident-Response Actions
| Priority | Action | Reason |
|---|---|---|
| P0 | Isolate WKS-FIN-07, WKS-ENG-12, WKS-HR-03 and SRV-FILE-01 | Stop encryption and attacker access |
| P0 | Disable `j.alvarez` sessions and rotate privileged credentials | Stolen administrator credentials enabled lateral movement |
| P0 | Block 203.0.113.55 and 203.0.113.77 in the simulated environment | Cut off staging and exfiltration infrastructure |
| P1 | Preserve volatile data and disk evidence before rebuilding | Support root-cause analysis and timeline validation |
| P1 | Restore from verified immutable backups | Shadow copies were deleted and cannot be trusted |
| P2 | Hunt for the listed IOCs and ATT&CK techniques across the fleet | Identify systems outside the known attack path |

## Analyst Assessment
**Severity: Critical. Confidence: High.** Multiple independent telemetry sources corroborate credential theft, privileged lateral movement, large outbound data transfer, recovery inhibition, and mass file renaming. The allowed 1.8 GB outbound transfer means data exfiltration should be treated as likely until proxy, DLP, and destination-side evidence proves otherwise.
