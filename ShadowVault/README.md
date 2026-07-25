# Operation ShadowVault — Ransomware Incident Response Simulation

A self-contained SOC/DFIR portfolio project: a synthetic multi-source log
dataset simulating a full ransomware kill chain, plus a Python detection
and correlation engine that reconstructs the incident from the logs alone
— stage by stage — and produces an analyst-style incident report.

**Scenario:** A manufacturing company detects unusual activity on a
Windows endpoint. Employees report slow systems and missing files.
Investigation reveals a five-stage intrusion:

```
Initial Access → Credential Theft → Lateral Movement →
Data Exfiltration Attempt → Ransomware Deployment
```

> **Scope note:** This project analyzes and detects simulated attacker
> *behavior* recorded in log data. It does not contain or execute any
> functional exploit, credential-dumping, or ransomware/encryption code —
> the "attack" exists only as realistic log rows for the detection
> pipeline to find, exactly like the public BOTS / DetectionLab-style
> training datasets used in real SOC training.

## Why this project

Most portfolio "security projects" are either a static writeup or a
single script. This one is structured the way real detection engineering
work is: independent, technique-scoped detectors (one per MITRE ATT&CK
technique) feeding a correlation layer that builds a unified timeline and
risk score — the same pattern a SIEM correlation rule set follows.

## Architecture

```
ShadowVault/
├── data/
│   ├── raw/                  # synthetic log sources (generated)
│   │   ├── windows_security_events.csv
│   │   ├── sysmon_events.csv
│   │   ├── network_firewall_logs.csv
│   │   └── file_activity_logs.csv
│   └── processed/            # correlation engine output
│       ├── incident_timeline.csv
│       ├── host_risk_scores.csv
│       └── attack_chain_summary.csv
├── src/
│   ├── log_generator.py      # builds the synthetic dataset (noise + attack chain)
│   ├── utils.py               # shared log-loading / alert helpers
│   ├── correlation_engine.py  # runs all detectors, builds timeline + risk scores
│   ├── report_generator.py    # renders the Markdown incident report
│   └── detectors/
│       ├── initial_access.py      # T1566.001 / T1204.002 / T1059.001
│       ├── credential_access.py   # T1003.001
│       ├── lateral_movement.py    # T1021.002 / T1569.002
│       ├── exfiltration.py        # T1560 / T1041
│       └── ransomware.py          # T1490 / T1486 / T1070.001
├── notebooks/
│   └── ShadowVault_Analysis.ipynb # full walkthrough with plotly visualizations
├── docs/
│   └── MITRE_ATTACK_MAPPING.md    # technique-to-ID reference + attack flow diagram
├── reports/
│   └── incident_report.md         # generated incident report (sample included)
└── requirements.txt
```

## How the dataset works

`src/log_generator.py` builds a full business day of activity across 6
hosts and 7 accounts at a fictional manufacturing company: normal logons,
routine file saves, and browsing traffic, with the five-stage attack
chain embedded at realistic points in the timeline. It's seeded
(`RNG_SEED = 1337`) for reproducibility. External/attacker IPs use the
IANA-reserved documentation range `203.0.113.0/24` — not real addresses.

## Results (sample run)

| Stage | Alerts | Window |
|---|---|---|
| 1 — Initial Access | 1 | 09:16:12 |
| 2 — Credential Theft | 2 | 09:45:09 – 09:45:20 |
| 3 — Lateral Movement | 5 | 10:30:20 – 11:07:43 |
| 4 — Data Exfiltration Attempt | 3 | 12:31:00 – 12:51:30 |
| 5 — Ransomware Deployment | 16 | 14:00:39 – 14:30:45 |

**Top-risk hosts:** WKS-FIN-07 (patient zero, score 20), SRV-FILE-01 (file
server, score 18) — matching the actual attack path.

27 alerts fired against ~200 rows of benign background noise with **zero
false positives**, because every detector targets one specific,
well-documented technique signature rather than generic anomaly scoring.

## Running it

```bash
pip install -r requirements.txt

# 1. Generate the synthetic dataset
python src/log_generator.py

# 2. Run detection + correlation
python src/correlation_engine.py

# 3. Generate the incident report
python src/report_generator.py

# 4. Or explore interactively:
jupyter notebook notebooks/ShadowVault_Analysis.ipynb
```

Each detector can also be run standalone for testing, e.g.
`python src/detectors/ransomware.py`.

## SOC dashboard

After generating the dataset and running the correlation engine, launch the
interactive investigation dashboard:

```bash
streamlit run dashboard.py
```

The dashboard provides an attack timeline, per-host risk scores, stage coverage,
filterable evidence, and a CSV export for filtered alerts.

## MITRE ATT&CK Coverage

See [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md) for the
full technique table and attack flow diagram.

## Possible extensions

- A sixth detector for C2 beaconing (regular-interval outbound connections).
- Replace the severity-weighted risk score with a proper anomaly-detection model.
- Feed `data/processed/incident_timeline.csv` into a live dashboard (e.g. Streamlit).
- Parameterize `log_generator.py` to emit variant attack chains for a small "CTF" set of scenarios.

## Resume framing

> Built an end-to-end ransomware incident-response simulation: engineered
> a synthetic multi-source log dataset (Windows Security, Sysmon,
> firewall, file-activity) modeling a 5-stage intrusion, then wrote a
> Python detection engine (5 MITRE ATT&CK-mapped detectors + a
> correlation/timeline/risk-scoring layer) that reconstructs the full
> attack chain and auto-generates an incident report, achieving 100%
> detection with zero false positives against background noise.
