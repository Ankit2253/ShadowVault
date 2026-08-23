import csv
import json
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = PROJECT_ROOT / "data" / "scenarios"
MANIFEST_PATH = SCENARIOS_DIR / "manifest.json"


class ScenarioManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with MANIFEST_PATH.open(encoding="utf-8") as manifest_file:
            cls.manifest = json.load(manifest_file)

    def test_manifest_contains_seven_unique_scenarios(self):
        scenarios = self.manifest["scenarios"]
        scenario_ids = [scenario["id"] for scenario in scenarios]
        scenario_slugs = [scenario["slug"] for scenario in scenarios]

        self.assertEqual(len(scenarios), 7)
        self.assertEqual(len(scenario_ids), len(set(scenario_ids)))
        self.assertEqual(len(scenario_slugs), len(set(scenario_slugs)))

    def test_all_scenario_directories_exist(self):
        for scenario in self.manifest["scenarios"]:
            scenario_dir = SCENARIOS_DIR / scenario["slug"]

            self.assertTrue((scenario_dir / "raw").is_dir())
            self.assertTrue((scenario_dir / "ground_truth").is_dir())

    def test_ready_scenario_contains_required_files(self):
        required_raw_files = set(self.manifest["telemetry_files"])
        ground_truth_name = self.manifest["ground_truth_file"]

        for scenario in self.manifest["scenarios"]:
            if scenario["status"] != "ready":
                continue

            scenario_dir = SCENARIOS_DIR / scenario["slug"]

            for filename in required_raw_files:
                self.assertTrue((scenario_dir / "raw" / filename).is_file())

            self.assertTrue(
                (scenario_dir / "ground_truth" / ground_truth_name).is_file()
            )

    def test_ransomware_ground_truth_schema_and_count(self):
        ground_truth_path = (
            SCENARIOS_DIR
            / "01_ransomware_full"
            / "ground_truth"
            / "expected_alerts.csv"
        )

        with ground_truth_path.open(newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            rows = list(reader)

        self.assertEqual(
            reader.fieldnames,
            ["Stage", "MITRE_ID", "Timestamp", "Hostname"],
        )
        self.assertEqual(len(rows), 27)


if __name__ == "__main__":
    unittest.main()
