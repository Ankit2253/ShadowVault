# ShadowVault Portfolio and Interview Guide

## Best GitHub description

> End-to-end Python SOC/DFIR lab: synthetic Windows/Sysmon/firewall/file telemetry, five MITRE ATT&CK-mapped ransomware detectors, alert correlation, risk scoring, labelled evaluation, automated CI tests, Streamlit dashboard, and incident reporting.

## CV bullet

> Built an end-to-end Python SOC/DFIR lab that generated and correlated 210 Windows, Sysmon, firewall, and file events across a five-stage ransomware scenario; implemented five ATT&CK-mapped detection modules, asset risk scoring, labelled evaluation, automated CI validation, a Streamlit investigation dashboard, and an incident report.

## Shorter CV bullet

> Developed a Python ransomware detection lab using Windows, Sysmon, firewall, and file telemetry; correlated 27 ATT&CK-mapped alerts into a five-stage incident timeline with risk scoring, tests, dashboarding, and automated reporting.

## 60-second interview explanation

“Operation ShadowVault is a safe SOC and incident-response simulation I built in Python. It generates 210 synthetic events across Windows Security, Sysmon, firewall, and file-activity logs, with one ransomware intrusion hidden inside normal activity. I wrote five technique-scoped detectors for phishing execution, LSASS access, lateral movement, exfiltration, and ransomware impact. A correlation layer normalizes the results into a timeline and calculates per-host risk scores. I also added labelled ground truth, automated validation, GitHub CI, a Streamlit investigation dashboard, and an analyst-style incident report. The key lesson was that one alert is rarely enough—the confidence comes from correlating independent telemetry sources across time, host, account, and ATT&CK technique.”

## Five-minute demonstration

1. Run `python run_pipeline.py` and show that every stage completes.
2. Open `data/processed/attack_chain_summary.csv` and explain the five-stage sequence.
3. Launch `streamlit run dashboard.py` and filter to `WKS-FIN-07`.
4. Walk from Word spawning PowerShell to LSASS access on the same host.
5. Switch to `SRV-FILE-01` and show lateral movement, archive staging, and outbound transfer.
6. Open `reports/incident_report.md` and explain containment and recovery priorities.
7. Run `python -m unittest discover -s tests -v` to demonstrate repeatability and validation.
8. Switch to “Upload my CSV logs” and explain schema validation, in-memory analysis, and why synthetic F1 is disabled for unknown data.

## Questions recruiters may ask

### Why did you use several log sources?

No single source shows the whole incident. Sysmon provides process and LSASS access evidence, Windows Security provides logons and service creation, firewall logs show movement and egress, and file telemetry shows staging and encryption behavior. Correlation turns those partial views into one investigation.

### Why is the server the highest-risk asset?

`SRV-FILE-01` contains evidence from lateral movement, privileged service execution, archive staging, large outbound transfer, recovery inhibition, audit-log clearing, and file encryption. The score accumulates severity weights from all of those alerts.

### Does F1 = 1.0 mean the detector is production ready?

No. It means the rules exactly recover the labelled behaviors in this deterministic lab without additional alerts. Production performance would require varied attacks, clean baselines, adversarial cases, tuning, and validation against real organizational telemetry.

### What would you improve next?

I would add C2 beaconing detection, Sigma equivalents, multiple randomized scenarios, clean-only baseline datasets, ATT&CK tactic fields, a real SIEM ingestion path, and unit tests for threshold edge cases.

### What was the most important engineering fix?

Normalizing firewall source IPs to asset names before risk scoring. Without that, `10.10.5.10` and `SRV-FILE-01` appeared as two different entities even though they were the same file server, which distorted the asset count and ranking.

## Honest wording to use

- Say “synthetic benchmark” rather than “production accuracy.”
- Say “simulated attacker behavior in logs” rather than “I deployed ransomware.”
- Say “attempted/likely exfiltration” because network volume alone does not prove what data reached the destination.
- Explain how you would validate and tune the rules on real data.

## GitHub presentation checklist

- Pin the repository on your profile.
- Add topics: `soc`, `dfir`, `detection-engineering`, `ransomware`, `mitre-attack`, `sysmon`, `streamlit`, `python`.
- Keep the generated incident report and processed sample outputs committed.
- Confirm the GitHub Actions workflow is green.
- Add one dashboard screenshot to the README after running it locally.
- Link the repository from your CV project title.
