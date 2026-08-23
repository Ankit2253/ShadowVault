# ShadowVault v1.1 Scenario Dataset

ShadowVault v1.1 evaluates the detection pipeline against multiple labelled
scenarios instead of one perfectly matched synthetic incident.

| ID | Scenario | Purpose |
|---|---|---|
| 01 | Full ransomware attack | Preserve the original five-stage benchmark |
| 02 | Clean business day | Measure false positives on normal activity |
| 03 | Partial phishing attack | Test detection with an incomplete attack chain |
| 04 | Authorized LSASS access | Create a realistic credential-access false positive |
| 05 | IT maintenance | Test legitimate remote administration and service creation |
| 06 | Authorized backup | Test large approved outbound transfers |
| 07 | Stealth attack | Measure false negatives against less obvious attacker behavior |

Each scenario contains:

- `raw/` — Windows Security, Sysmon, firewall and file-activity CSV files.
- `ground_truth/` — labelled alerts that should be detected.
