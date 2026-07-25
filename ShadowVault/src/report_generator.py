"""
Operation ShadowVault - Incident Report Generator
====================================================
Takes the correlated timeline/risk/summary output from correlation_engine.py
and renders a Markdown incident report suitable for a SOC case file or a
portfolio writeup.
"""

import sys
from pathlib import Path
from datetime import datetime

sys.path.append(str(Path(__file__).resolve().parent))
from correlation_engine import run_all_detectors, score_by_host, attack_chain_summary

REPORT_PATH = Path(__file__).resolve().parent.parent / "reports" / "incident_report.md"

SEVERITY_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


def build_report(timeline, risk, summary):
    lines = []
    lines.append("# Incident Report: Operation ShadowVault")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ")
    lines.append("**Classification:** Simulated Incident (Training Exercise)  ")
    lines.append("**Organization:** Meridian Precision Manufacturing (fictional)  ")
    lines.append("**Incident Date:** 2026-07-14\n")

    lines.append("## Executive Summary")
    n_hosts = timeline["Hostname"].nunique()
    start, end = timeline["Timestamp"].min(), timeline["Timestamp"].max()
    duration = end - start
    lines.append(
        f"On 2026-07-14, an employee in Accounts Payable opened a malicious attachment "
        f"delivered via email, triggering a five-stage intrusion that progressed from "
        f"initial access to full ransomware deployment in approximately "
        f"**{duration.total_seconds()/3600:.1f} hours**. The attacker dumped credentials "
        f"from a compromised finance workstation, used a stolen IT administrator account "
        f"to move laterally across **{n_hosts} hosts**, staged and attempted to exfiltrate "
        f"proprietary data to external infrastructure, and ultimately deployed ransomware "
        f"that deleted shadow copy backups and encrypted files across four endpoints and "
        f"the file server. This report reconstructs the full attack chain from correlated "
        f"log data.\n"
    )

    lines.append("## Attack Chain Overview")
    lines.append("| Stage | Alerts | First Observed | Last Observed |")
    lines.append("|---|---|---|---|")
    for _, row in summary.iterrows():
        lines.append(f"| {row['Stage']} | {row['Alerts']} | {row['First_Seen']} | {row['Last_Seen']} |")
    lines.append("")

    lines.append("## Host Risk Ranking")
    lines.append("| Host | Risk Score |")
    lines.append("|---|---|")
    for _, row in risk.iterrows():
        lines.append(f"| {row['Hostname']} | {row['RiskScore']} |")
    lines.append("")

    lines.append("## Detailed Timeline\n")
    for stage, group in timeline.groupby("Stage", sort=False):
        lines.append(f"### {stage}")
        for _, row in group.sort_values("Timestamp").iterrows():
            icon = SEVERITY_ICON.get(row["Severity"], "")
            lines.append(
                f"- **{row['Timestamp']}** {icon} `{row['MITRE_ID']}` — "
                f"{row['Technique']} on **{row['Hostname']}** "
                f"(account: {row['Account']})  \n"
                f"  _{row['Detail']}_"
            )
        lines.append("")

    lines.append("## Indicators of Compromise (IOCs)")
    lines.append("| Type | Value |")
    lines.append("|---|---|")
    lines.append("| External IP (stager) | 203.0.113.55 |")
    lines.append("| External IP (exfil destination) | 203.0.113.77 |")
    lines.append("| File | Invoice_84421.docm |")
    lines.append("| File | svchost_upd.exe |")
    lines.append("| File | encryptor.exe |")
    lines.append("| File extension | *.shadowvault |")
    lines.append("| File | !!!RECOVER_YOUR_FILES!!!.txt |")
    lines.append("| Compromised account | j.alvarez (IT admin, credentials stolen) |")
    lines.append("")

    lines.append("## Recommendations")
    lines.append("- Enforce macro execution restrictions (block macros from internet-sourced Office files) to close the initial access vector.")
    lines.append("- Deploy LSASS access protections (Credential Guard / PPL) to prevent memory dumping.")
    lines.append("- Restrict and monitor use of administrative accounts for interactive/network logons across multiple hosts.")
    lines.append("- Alert on `vssadmin delete shadows` and similar shadow-copy deletion commands.")
    lines.append("- Implement DLP egress filtering and alerting on large outbound transfers to unfamiliar external hosts.")
    lines.append("- Maintain offline/immutable backups so shadow-copy deletion cannot prevent recovery.")
    lines.append("")

    return "\n".join(lines)


def main():
    timeline, risk, summary = run_all_detectors(), None, None
    risk = score_by_host(timeline)
    summary = attack_chain_summary(timeline)

    report_text = build_report(timeline, risk, summary)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report_text, encoding="utf-8")
    print(f"Incident report written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
