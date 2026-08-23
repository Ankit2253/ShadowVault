import sys
import unittest
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from correlation_engine import attack_chain_summary, correlate_logs, run_all_detectors, score_by_host
from evaluate import evaluate
from log_generator import main as generate_logs
from report_generator import build_uploaded_report
from utils import load_logs, normalize_log_frame


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate_logs()

    def test_end_to_end_attack_chain(self):
        timeline = run_all_detectors()
        summary = attack_chain_summary(timeline)

        self.assertEqual(len(timeline), 27)
        self.assertEqual(timeline["Stage"].nunique(), 5)
        self.assertEqual(summary["Alerts"].tolist(), [1, 2, 5, 3, 16])
        self.assertTrue(timeline["Timestamp"].is_monotonic_increasing)

    def test_risk_ranking_uses_asset_names(self):
        risk = score_by_host(run_all_detectors())

        self.assertEqual(risk.iloc[0]["Hostname"], "SRV-FILE-01")
        self.assertEqual(risk.iloc[0]["RiskScore"], 23)
        self.assertFalse(risk["Hostname"].str.match(r"^\d+\.\d+\.\d+\.\d+$").any())

    def test_labelled_synthetic_benchmark(self):
        metrics = evaluate(run_all_detectors())

        self.assertEqual(metrics["true_positives"], 27)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["f1_score"], 1.0)

    def test_uploaded_frames_use_the_same_detection_pipeline(self):
        timeline = correlate_logs(*load_logs())

        self.assertEqual(len(timeline), 27)
        self.assertEqual(timeline["Stage"].nunique(), 5)

    def test_uploaded_schema_validation_identifies_missing_columns(self):
        incomplete = pd.DataFrame({"Timestamp": ["2026-07-14 09:00:00"]})

        with self.assertRaisesRegex(ValueError, "missing columns"):
            normalize_log_frame(incomplete, "sysmon_events.csv")

    def test_uploaded_report_uses_neutral_scope(self):
        timeline = correlate_logs(*load_logs())
        report = build_uploaded_report(
            timeline,
            score_by_host(timeline),
            attack_chain_summary(timeline),
        )

        self.assertIn("User-supplied telemetry", report)
        self.assertIn("require analyst validation", report)
        self.assertNotIn("Meridian Precision", report)


if __name__ == "__main__":
    unittest.main()
