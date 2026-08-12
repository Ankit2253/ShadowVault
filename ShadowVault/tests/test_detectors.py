import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from detectors import credential_access, exfiltration, initial_access, lateral_movement, ransomware
from log_generator import main as generate_logs
from utils import load_logs


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate_logs()

    def test_each_attack_stage_produces_expected_alert_count(self):
        security, sysmon, firewall, files = load_logs()

        self.assertEqual(len(initial_access.detect(sysmon)), 1)
        self.assertEqual(len(credential_access.detect(sysmon, files)), 2)
        self.assertEqual(len(lateral_movement.detect(security, sysmon)), 5)
        self.assertEqual(len(exfiltration.detect(sysmon, firewall)), 3)
        self.assertEqual(len(ransomware.detect(sysmon, security, files)), 16)

    def test_exfiltration_ip_is_resolved_to_asset_name(self):
        _, sysmon, firewall, _ = load_logs()
        alerts = exfiltration.detect(sysmon, firewall)
        transfer_alerts = [alert for alert in alerts if alert["MITRE_ID"] == "T1041"]

        self.assertEqual(len(transfer_alerts), 2)
        self.assertEqual({alert["Hostname"] for alert in transfer_alerts}, {"SRV-FILE-01"})

    def test_all_alerts_use_the_standard_schema(self):
        security, sysmon, firewall, files = load_logs()
        alerts = (
            initial_access.detect(sysmon)
            + credential_access.detect(sysmon, files)
            + lateral_movement.detect(security, sysmon)
            + exfiltration.detect(sysmon, firewall)
            + ransomware.detect(sysmon, security, files)
        )
        expected_fields = {
            "Stage", "Technique", "MITRE_ID", "Timestamp",
            "Hostname", "Account", "Detail", "Severity",
        }

        self.assertTrue(alerts)
        self.assertTrue(all(set(alert) == expected_fields for alert in alerts))


if __name__ == "__main__":
    unittest.main()
