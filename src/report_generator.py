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
    lines.append("**Incident Date:** 2026-07-14  ")
    lines.append("**Case Status:** Contained; recovery and credential reset required\n")

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
        f"to move laterally across the environment, staged and attempted to exfiltrate "
        f"proprietary data to external infrastructure, and ultimately deployed ransomware "
        f"that deleted shadow copy backups and encrypted files across three workstations and "
        f"the file server. This report reconstructs the full attack chain from correlated "
        f"log data. Alert evidence was observed on **{n_hosts} named assets**.\n"
    )

    lines.append("## Scope and Confidence")
    lines.append(
        "This report is produced from a deterministic, labelled training dataset. "
        "The detections provide high-confidence evidence for this scenario, but the "
        "benchmark results must not be interpreted as production detection performance.\n"
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

    lines.append("## Incident-Response Actions")
    lines.append("| Priority | Action | Reason |")
    lines.append("|---|---|---|")
    lines.append("| P0 | Isolate WKS-FIN-07, WKS-ENG-12, WKS-HR-03 and SRV-FILE-01 | Stop encryption and attacker access |")
    lines.append("| P0 | Disable `j.alvarez` sessions and rotate privileged credentials | Stolen administrator credentials enabled lateral movement |")
    lines.append("| P0 | Block 203.0.113.55 and 203.0.113.77 in the simulated environment | Cut off staging and exfiltration infrastructure |")
    lines.append("| P1 | Preserve volatile data and disk evidence before rebuilding | Support root-cause analysis and timeline validation |")
    lines.append("| P1 | Restore from verified immutable backups | Shadow copies were deleted and cannot be trusted |")
    lines.append("| P2 | Hunt for the listed IOCs and ATT&CK techniques across the fleet | Identify systems outside the known attack path |")
    lines.append("")

    lines.append("## Analyst Assessment")
    lines.append(
        "**Severity: Critical. Confidence: High.** Multiple independent telemetry sources "
        "corroborate credential theft, privileged lateral movement, large outbound data "
        "transfer, recovery inhibition, and mass file renaming. The allowed 1.8 GB outbound "
        "transfer means data exfiltration should be treated as likely until proxy, DLP, and "
        "destination-side evidence proves otherwise."
    )
    lines.append("")

    return "\n".join(lines)


def build_uploaded_report(timeline, risk, summary):
    """Build a neutral report for user-supplied telemetry without scenario claims."""
    lines = [
        "# ShadowVault Detection Report: Uploaded Telemetry",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        "**Classification:** User-supplied telemetry analysis  ",
        "**Scope:** Detection results from the five included ShadowVault rule modules\n",
        "## Executive Summary",
    ]

    start, end = timeline["Timestamp"].min(), timeline["Timestamp"].max()
    lines.append(
        f"ShadowVault generated **{len(timeline)} alerts** across "
        f"**{timeline['Stage'].nunique()} attack stages** and "
        f"**{timeline['Hostname'].nunique()} assets**. Matching activity was observed from "
        f"**{start}** to **{end}**. These rule matches require analyst validation and do not, "
        "by themselves, prove compromise.\n"
    )

    lines.extend([
        "## Important Scope Note",
        "This analysis only covers the schemas and detection behaviors implemented in "
        "ShadowVault. No synthetic ground-truth score is applied to uploaded data. A result "
        "with zero alerts does not prove that an environment is clean.\n",
        "## Attack-Chain Summary",
        "| Stage | Alerts | First Observed | Last Observed |",
        "|---|---|---|---|",
    ])
    for _, row in summary.iterrows():
        lines.append(f"| {row['Stage']} | {row['Alerts']} | {row['First_Seen']} | {row['Last_Seen']} |")

    lines.extend(["", "## Asset Risk Ranking", "| Asset | Risk Score |", "|---|---:|"])
    for _, row in risk.iterrows():
        lines.append(f"| {row['Hostname']} | {row['RiskScore']} |")

    lines.extend(["", "## Alert Evidence"])
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

    lines.extend([
        "## Recommended Analyst Actions",
        "- Validate each alert against authorized EDR, identity, network, and asset context.",
        "- Determine whether the observed accounts, tools, transfers, and administrative actions were approved.",
        "- Isolate affected assets if malicious encryption, credential access, or uncontrolled lateral movement is confirmed.",
        "- Preserve relevant volatile and disk evidence before rebuilding systems.",
        "- Expand the hunt using confirmed indicators and adjacent telemetry sources.",
        "",
    ])
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
