"""Evaluate detector output against the labelled synthetic scenario."""

import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent))
from correlation_engine import run_all_detectors


PROJECT_DIR = Path(__file__).resolve().parent.parent
GROUND_TRUTH_PATH = PROJECT_DIR / "data" / "ground_truth" / "expected_alerts.csv"
METRICS_PATH = PROJECT_DIR / "data" / "processed" / "evaluation_metrics.json"
KEY_COLUMNS = ["Stage", "MITRE_ID", "Timestamp", "Hostname"]


def _keys(frame):
    normalized = frame.copy()
    normalized["Timestamp"] = pd.to_datetime(normalized["Timestamp"])
    return Counter(tuple(row) for row in normalized[KEY_COLUMNS].itertuples(index=False, name=None))


def evaluate(timeline=None, expected_path=GROUND_TRUTH_PATH):
    """Return exact-match precision/recall metrics for the fixed lab scenario."""
    if timeline is None:
        timeline = run_all_detectors()
    expected = pd.read_csv(expected_path, parse_dates=["Timestamp"])

    actual_keys = _keys(timeline)
    expected_keys = _keys(expected)
    true_positives = sum((actual_keys & expected_keys).values())
    false_positives = sum((actual_keys - expected_keys).values())
    false_negatives = sum((expected_keys - actual_keys).values())

    precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 0.0
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "benchmark": "labelled synthetic ShadowVault scenario",
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "expected_alerts": sum(expected_keys.values()),
        "generated_alerts": sum(actual_keys.values()),
        "scope_note": "Metrics describe this deterministic training dataset only; they are not production performance claims.",
    }


def main():
    metrics = evaluate()
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    print(f"Wrote evaluation metrics to {METRICS_PATH}")
    return metrics


if __name__ == "__main__":
    main()
