"""
Operation ShadowVault - Synthetic Log Generator
=================================================
Generates a realistic multi-source log dataset for a simulated ransomware
incident at a fictional manufacturing company (Meridian Precision Mfg).

Produces four log sources into data/raw/:
    - windows_security_events.csv   (Windows Security Event Log style)
    - sysmon_events.csv             (Sysmon operational log style)
    - network_firewall_logs.csv     (perimeter firewall / proxy log style)
    - file_activity_logs.csv        (endpoint file-system activity)

The dataset mixes normal business-day "noise" with a deliberately embedded
five-stage attack chain (Initial Access -> Credential Theft -> Lateral
Movement -> Data Exfiltration Attempt -> Ransomware Deployment) so the
detection modules in src/detectors/ have something realistic to find.

All external/attacker IPs use the IANA-reserved TEST-NET-3 documentation
range (203.0.113.0/24) - these are not real, routable addresses.
This script generates DATA ONLY (log rows describing what would be
observed). It contains no functional exploit, credential-dumping, or
encryption code.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

RNG_SEED = 1337
random.seed(RNG_SEED)

INCIDENT_DATE = datetime(2026, 7, 14)  # a Tuesday
OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

# ---------------------------------------------------------------------------
# Environment definition
# ---------------------------------------------------------------------------

HOSTS = {
    "WKS-FIN-07": "10.10.12.47",   # patient zero - Accounts Payable
    "WKS-ENG-12": "10.10.14.22",
    "WKS-HR-03":  "10.10.16.9",
    "WKS-IT-02":  "10.10.20.5",
    "SRV-FILE-01": "10.10.5.10",
    "SRV-DC-01":  "10.10.5.1",
}

USERS = {
    "s.jenkins": "WKS-FIN-07",   # phishing victim
    "j.alvarez": "WKS-IT-02",    # IT admin, creds stolen from LSASS
    "m.chen":    "WKS-ENG-12",
    "r.patel":   "WKS-HR-03",
    "t.oconnor": "WKS-ENG-12",
    "k.wright":  "WKS-HR-03",
    "svc_backup": "SRV-FILE-01",
}

ATTACKER_STAGER_IP = "203.0.113.55"
ATTACKER_EXFIL_IP = "203.0.113.77"

sec_rows, sysmon_rows, fw_rows, file_rows = [], [], [], []


def t(hh, mm, ss=0):
    return INCIDENT_DATE.replace(hour=hh, minute=mm, second=ss)


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 1. Background noise - a normal business day
# ---------------------------------------------------------------------------

def generate_noise():
    logon_types = {2: "Interactive", 3: "Network", 10: "RemoteInteractive"}
    benign_procs = [
        ("outlook.exe", "explorer.exe"),
        ("chrome.exe", "explorer.exe"),
        ("teams.exe", "explorer.exe"),
        ("excel.exe", "explorer.exe"),
        ("onedrive.exe", "explorer.exe"),
        ("acrord32.exe", "chrome.exe"),
    ]

    for user, host in USERS.items():
        # normal morning badge-in / logon
        logon_time = t(8, random.randint(0, 45), random.randint(0, 59))
        sec_rows.append([ts(logon_time), host, 4624, "An account was successfully logged on",
                          user, "MERIDIAN", HOSTS[host], 2, "Success"])

        # scattered benign process activity through the day
        for _ in range(random.randint(6, 12)):
            proc, parent = random.choice(benign_procs)
            pt = t(random.randint(8, 16), random.randint(0, 59), random.randint(0, 59))
            sysmon_rows.append([ts(pt), host, 1, proc, "", parent, "", user,
                                 "", "", "", "", ""])

        # occasional benign external browsing traffic
        for _ in range(random.randint(3, 6)):
            ft = t(random.randint(8, 16), random.randint(0, 59), random.randint(0, 59))
            fw_rows.append([ts(ft), HOSTS[host], random.randint(49200, 60000),
                             f"93.184.{random.randint(1,254)}.{random.randint(1,254)}",
                             443, "TCP", "Allow", random.randint(2000, 90000),
                             random.randint(2000, 500000), "Outbound"])

        # a couple of routine failed logons (typos, expired passwords)
        if random.random() < 0.4:
            ft = t(random.randint(8, 16), random.randint(0, 59))
            sec_rows.append([ts(ft), host, 4625, "An account failed to log on",
                              user, "MERIDIAN", HOSTS[host], 3, "Failure"])

    # unrelated routine file saves across the fleet
    routine_files = ["Q3_budget_draft.xlsx", "meeting_notes.docx", "vendor_list.csv",
                      "timesheet.xlsx", "presentation_v2.pptx"]
    for user, host in USERS.items():
        for _ in range(random.randint(2, 5)):
            ft = t(random.randint(8, 16), random.randint(0, 59), random.randint(0, 59))
            fname = random.choice(routine_files)
            file_rows.append([ts(ft), host, user, f"C:\\Users\\{user}\\Documents\\{fname}",
                               "Modified", fname.split(".")[-1], "", "WINWORD.EXE",
                               random.randint(20_000, 900_000)])


# ---------------------------------------------------------------------------
# 2. Stage 1 - Initial Access (T1566.001 Phishing, T1204.002, T1059.001)
# ---------------------------------------------------------------------------

def stage_initial_access():
    host, ip, user = "WKS-FIN-07", HOSTS["WKS-FIN-07"], "s.jenkins"

    sec_rows.append([ts(t(9, 14, 2)), host, 4624, "An account was successfully logged on",
                      user, "MERIDIAN", ip, 2, "Success"])

    file_rows.append([ts(t(9, 14, 40)), host, user,
                       f"C:\\Users\\{user}\\Downloads\\Invoice_84421.docm",
                       "Created", "docm", "", "OUTLOOK.EXE", 88_412])

    sysmon_rows.append([ts(t(9, 14, 55)), host, 1, "WINWORD.EXE",
                         'winword.exe /n "Invoice_84421.docm"', "explorer.exe", "",
                         user, "", "", "", "", ""])

    # macro spawns an obfuscated PowerShell child process - classic phish->exec
    sysmon_rows.append([ts(t(9, 16, 12)), host, 1, "powershell.exe",
                         "powershell.exe -nop -w hidden -enc <base64-encoded-command>",
                         "WINWORD.EXE", "winword.exe", user, "", "", "", "", ""])
    sec_rows.append([ts(t(9, 16, 12)), host, 4688, "A new process has been created",
                      user, "MERIDIAN", ip, "", "",])

    # stager download from attacker infra
    sysmon_rows.append([ts(t(9, 16, 40)), host, 3, "powershell.exe", "", "", "", user,
                         "", "", ATTACKER_STAGER_IP, 443, "TCP"])
    fw_rows.append([ts(t(9, 16, 40)), ip, random.randint(49300, 50000),
                     ATTACKER_STAGER_IP, 443, "TCP", "Allow", 4_200, 812_004, "Outbound"])

    file_rows.append([ts(t(9, 17, 5)), host, user,
                       f"C:\\Users\\{user}\\AppData\\Local\\Temp\\svchost_upd.exe",
                       "Created", "exe", "", "powershell.exe", 412_336])


# ---------------------------------------------------------------------------
# 3. Stage 2 - Credential Theft (T1003.001 LSASS Memory)
# ---------------------------------------------------------------------------

def stage_credential_theft():
    host, ip, user = "WKS-FIN-07", HOSTS["WKS-FIN-07"], "s.jenkins"

    sysmon_rows.append([ts(t(9, 45, 2)), host, 1, "svchost_upd.exe", "svchost_upd.exe --dump",
                         "powershell.exe", "", user, "", "", "", "", ""])

    # process access to lsass.exe with a suspicious access mask - the
    # canonical Sysmon Event ID 10 signature for credential dumping tools
    sysmon_rows.append([ts(t(9, 45, 9)), host, 10, "svchost_upd.exe", "", "", "", user,
                         "C:\\Windows\\System32\\lsass.exe", "0x1010", "", ""])

    file_rows.append([ts(t(9, 45, 20)), host, user,
                       f"C:\\Users\\{user}\\AppData\\Local\\Temp\\lsass_dump.tmp",
                       "Created", "tmp", "", "svchost_upd.exe", 61_204_112])

    # dumped credentials for the IT admin are used ~40 min later
    sec_rows.append([ts(t(10, 24, 0)), host, 4672,
                      "Special privileges assigned to new logon",
                      "j.alvarez", "MERIDIAN", ip, "", "Success"])


# ---------------------------------------------------------------------------
# 4. Stage 3 - Lateral Movement (T1021.002 SMB/Windows Admin Shares,
#    T1569.002 Service Execution)
# ---------------------------------------------------------------------------

def stage_lateral_movement():
    targets = ["WKS-ENG-12", "WKS-HR-03", "SRV-FILE-01", "SRV-DC-01"]
    cursor = t(10, 30, 0)
    for host in targets:
        ip = HOSTS[host]
        logon_ts = cursor + timedelta(seconds=random.randint(0, 59))
        cursor += timedelta(minutes=random.randint(8, 15))

        sec_rows.append([ts(logon_ts), host, 4624, "An account was successfully logged on",
                          "j.alvarez", "MERIDIAN", HOSTS["WKS-FIN-07"], 3, "Success"])
        sec_rows.append([ts(logon_ts + timedelta(seconds=4)), host, 4672,
                          "Special privileges assigned to new logon",
                          "j.alvarez", "MERIDIAN", HOSTS["WKS-FIN-07"], "", "Success"])

        # remote service creation - PsExec-style lateral movement
        sec_rows.append([ts(logon_ts + timedelta(seconds=9)), host, 4697,
                          "A service was installed in the system",
                          "j.alvarez", "MERIDIAN", HOSTS["WKS-FIN-07"], "", ""])
        sysmon_rows.append([ts(logon_ts + timedelta(seconds=10)), host, 1, "psexesvc.exe",
                             "psexesvc.exe -accepteula \\\\%s -s cmd.exe" % host,
                             "services.exe", "", "j.alvarez", "", "", "", "", ""])

        fw_rows.append([ts(logon_ts + timedelta(seconds=2)), HOSTS["WKS-FIN-07"],
                         random.randint(49300, 50000), ip, 445, "TCP", "Allow",
                         12_400, 4_100, "Internal"])


# ---------------------------------------------------------------------------
# 5. Stage 4 - Data Exfiltration Attempt (T1560 Archive Collected Data,
#    T1041 Exfiltration Over C2 Channel)
# ---------------------------------------------------------------------------

def stage_exfiltration():
    host, ip, user = "SRV-FILE-01", HOSTS["SRV-FILE-01"], "j.alvarez"

    sysmon_rows.append([ts(t(12, 31, 0)), host, 1, "7z.exe",
                         '7z.exe a -mx1 archive_backup.7z "\\\\SRV-FILE-01\\Shared\\*"',
                         "cmd.exe", "", user, "", "", "", "", ""])

    for i, folder in enumerate(["Finance", "Engineering_Specs", "HR_Records", "Contracts"]):
        file_rows.append([ts(t(12, 32, 0) + timedelta(seconds=i * 20)), host, user,
                           f"\\\\SRV-FILE-01\\Shared\\{folder}\\*", "Read", "", "",
                           "7z.exe", random.randint(200_000_000, 900_000_000)])

    file_rows.append([ts(t(12, 40, 10)), host, user,
                       "C:\\Windows\\Temp\\archive_backup.7z",
                       "Created", "7z", "", "7z.exe", 3_412_004_221])

    # large outbound transfer - flagged and partially blocked by the
    # perimeter DLP/firewall once the volume threshold trips
    fw_rows.append([ts(t(12, 44, 0)), ip, random.randint(49300, 50000),
                     ATTACKER_EXFIL_IP, 443, "TCP", "Allow", 1_800_000_000, 12_000, "Outbound"])
    fw_rows.append([ts(t(12, 51, 30)), ip, random.randint(49300, 50000),
                     ATTACKER_EXFIL_IP, 443, "TCP", "Blocked", 210_000_000, 0, "Outbound"])


# ---------------------------------------------------------------------------
# 6. Stage 5 - Ransomware Deployment (T1490 Inhibit System Recovery,
#    T1486 Data Encrypted for Impact)
# ---------------------------------------------------------------------------

def stage_ransomware():
    targets = ["WKS-FIN-07", "WKS-ENG-12", "WKS-HR-03", "SRV-FILE-01"]

    for host in targets:
        dt = t(14, random.randint(0, 4), random.randint(0, 59))
        # anti-recovery: delete shadow copies before encrypting
        sysmon_rows.append([ts(dt), host, 1, "vssadmin.exe",
                             "vssadmin.exe delete shadows /all /quiet",
                             "cmd.exe", "", "j.alvarez", "", "", "", "", ""])
        sec_rows.append([ts(dt), host, 1102, "The audit log was cleared",
                          "j.alvarez", "MERIDIAN", HOSTS[host], "", ""])

    for host in targets:
        base = t(14, random.randint(6, 30), 0)
        enc_proc_ts = base
        sysmon_rows.append([ts(enc_proc_ts), host, 1, "encryptor.exe",
                             "encryptor.exe --target=C:\\Users --ext=.shadowvault",
                             "svchost_upd.exe", "", "j.alvarez", "", "", "", "", ""])

        for j, fname in enumerate(["Q3_budget_draft.xlsx", "vendor_list.csv",
                                    "engineering_specs.dwg", "hr_records.xlsx"]):
            rt = base + timedelta(seconds=j * 7)
            file_rows.append([ts(rt), host, "j.alvarez",
                               f"C:\\Users\\Shared\\{fname}", "Renamed", fname.split(".")[-1],
                               "shadowvault", "encryptor.exe", random.randint(50_000, 900_000)])

        note_ts = base + timedelta(seconds=45)
        file_rows.append([ts(note_ts), host, "j.alvarez",
                           "C:\\Users\\Shared\\!!!RECOVER_YOUR_FILES!!!.txt",
                           "Created", "", "txt", "encryptor.exe", 1_204])


# ---------------------------------------------------------------------------
# Write everything out
# ---------------------------------------------------------------------------

def write_csv(path, header, rows):
    rows_sorted = sorted(rows, key=lambda r: r[0])
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows_sorted)
    print(f"  wrote {len(rows_sorted):>4} rows -> {path.name}")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    generate_noise()
    stage_initial_access()
    stage_credential_theft()
    stage_lateral_movement()
    stage_exfiltration()
    stage_ransomware()

    print("Generating Operation ShadowVault synthetic dataset...")
    write_csv(OUT_DIR / "windows_security_events.csv",
              ["Timestamp", "Hostname", "EventID", "EventDescription", "Account",
               "Domain", "SourceIP", "LogonType", "Status"], sec_rows)
    write_csv(OUT_DIR / "sysmon_events.csv",
              ["Timestamp", "Hostname", "EventID", "Image", "CommandLine", "ParentImage",
               "ParentCommandLine", "User", "TargetImage", "GrantedAccess",
               "DestinationIP", "DestinationPort", "Protocol"], sysmon_rows)
    write_csv(OUT_DIR / "network_firewall_logs.csv",
              ["Timestamp", "SourceIP", "SourcePort", "DestinationIP", "DestinationPort",
               "Protocol", "Action", "BytesSent", "BytesReceived", "Direction"], fw_rows)
    write_csv(OUT_DIR / "file_activity_logs.csv",
              ["Timestamp", "Hostname", "Account", "FilePath", "Action",
               "OriginalExtension", "NewExtension", "ProcessName", "FileSizeBytes"], file_rows)
    print("Done.")


if __name__ == "__main__":
    main()
