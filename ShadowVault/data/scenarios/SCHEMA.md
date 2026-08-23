# ShadowVault v1.1 Scenario Schema

Each scenario contains two directories:

- `raw/` contains the four telemetry CSV files.
- `ground_truth/` contains `expected_alerts.csv`.

## Required telemetry files

Every ready scenario must contain:

1. `windows_security_events.csv`
2. `sysmon_events.csv`
3. `network_firewall_logs.csv`
4. `file_activity_logs.csv`

## Ground-truth format

The `expected_alerts.csv` file uses these columns:

| Column | Meaning |
|---|---|
| `Stage` | Attack stage assigned to the expected alert |
| `MITRE_ID` | MITRE ATT&CK technique or techniques |
| `Timestamp` | Timestamp of the evidence that should generate the alert |
| `Hostname` | Asset on which the activity occurred |

Each row represents one alert that the detection pipeline should generate.

## Labelling rules

- Malicious activity that should be detected is included in ground truth.
- Benign activity is excluded even when it resembles an attack.
- A clean scenario uses an `expected_alerts.csv` file containing only the header.
- A generated alert without a matching ground-truth row is a false positive.
- A ground-truth row without a matching generated alert is a false negative.
- Matching uses `Stage`, `MITRE_ID`, `Timestamp`, and `Hostname`.

Scenario 01 preserves the original deterministic ransomware benchmark with 27
labelled alerts.
