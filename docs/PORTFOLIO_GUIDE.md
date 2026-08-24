# ShadowVault Portfolio and Interview Guide

## Best GitHub description

> End-to-end SOC/DFIR lab combining Python detection engineering with an optional Yocto embedded-Linux endpoint, Wazuh/syslog telemetry, ATT&CK mapping, labelled evaluation, CI, dashboarding, and incident reporting.

## CV bullet

> Built an end-to-end SOC/DFIR lab that generated and correlated 219 Windows, Sysmon, firewall, and file events across a five-stage ransomware scenario; added a Yocto 6.0 embedded endpoint with audit/syslog forwarding to Wazuh, optional IoT detections, labelled evaluation, CI, dashboarding, and incident reporting.

## Shorter CV bullet

> Developed a Python ransomware detection lab using Windows, Sysmon, firewall, and file telemetry; correlated 27 ATT&CK-mapped alerts into a five-stage incident timeline with risk scoring, tests, dashboarding, and automated reporting.

## 60-second interview explanation

“Operation ShadowVault is a safe SOC and incident-response lab. Its Python pipeline generates 219 Windows, Sysmon, firewall, and file events and reconstructs a ransomware intrusion. I also built an optional Yocto 6.0 layer that turns an embedded Linux device into a monitored endpoint using auditd and queued syslog forwarding to Wazuh. A converter normalizes Wazuh exports, and separate detections cover SSH brute force, privileged execution, and security-logging changes. The core synthetic benchmark remains isolated so I can compare rule changes honestly.”

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

### Does the synthetic F1 score mean the detector is production ready?

No. The current benchmark deliberately includes two false negatives, giving an F1 of 0.9643. Production performance would still require varied attacks, clean baselines, adversarial cases, tuning, and validation against authorized organizational telemetry.

### What would you improve next?

I would run the Yocto layer through a real BitBake build on Wrynose, validate it on QEMU and target hardware, replace lab TCP syslog with authenticated encryption, add Wazuh decoders/rules, and measure false positives against a clean embedded-device baseline.

### What was the most important engineering fix?

Normalizing firewall source IPs to asset names before risk scoring. Without that, `10.10.5.10` and `SRV-FILE-01` appeared as two different entities even though they were the same file server, which distorted the asset count and ranking.

## Honest wording to use

- Say “synthetic benchmark” rather than “production accuracy.”
- Say “simulated attacker behavior in logs” rather than “I deployed ransomware.”
- Say “attempted/likely exfiltration” because network volume alone does not prove what data reached the destination.
- Explain how you would validate and tune the rules on real data.

## GitHub presentation checklist

- Pin the repository on your profile.
- Add topics: `soc`, `dfir`, `detection-engineering`, `ransomware`, `mitre-attack`, `yocto`, `embedded-linux`, `wazuh`, `streamlit`, `python`.
- Keep the generated incident report and processed sample outputs committed.
- Confirm the GitHub Actions workflow is green.
- Add one dashboard screenshot to the README after running it locally.
- Link the repository from your CV project title.
