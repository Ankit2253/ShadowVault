import json
import sys
import unittest
from pathlib import Path

import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from correlation_engine import correlate_logs
from detectors import yocto_endpoint
from utils import YOCTO_LOG_FILENAME, load_logs, normalize_log_frame
from yocto_adapter import wazuh_payload_to_frame


SAMPLE_PATH = PROJECT_DIR / "data" / "samples" / YOCTO_LOG_FILENAME


class YoctoIntegrationTests(unittest.TestCase):
    def load_sample(self):
        return normalize_log_frame(pd.read_csv(SAMPLE_PATH), YOCTO_LOG_FILENAME)

    def test_sample_yocto_telemetry_produces_three_alerts(self):
        alerts = yocto_endpoint.detect(self.load_sample())

        self.assertEqual(len(alerts), 3)
        self.assertEqual(
            {alert["MITRE_ID"] for alert in alerts},
            {"T1110.001", "T1548.003", "T1562.001"},
        )
        self.assertTrue(all(alert["Hostname"] == "IOT-GW-01" for alert in alerts))

    def test_optional_yocto_frame_joins_the_incident_timeline(self):
        timeline = correlate_logs(*load_logs(), yocto=self.load_sample())

        self.assertEqual(len(timeline), 30)
        self.assertIn("Embedded Endpoint Monitoring", set(timeline["Stage"]))

    def test_wazuh_search_response_is_normalized(self):
        payload = {
            "hits": {
                "hits": [{
                    "_source": {
                        "timestamp": "2026-07-14T15:00:00Z",
                        "agent": {"name": "IOT-GW-01", "ip": "10.10.30.15"},
                        "predecoder": {"program_name": "sshd"},
                        "full_log": (
                            "Failed password for invalid user admin "
                            "from 203.0.113.90 port 49152 ssh2"
                        ),
                    }
                }]
            }
        }

        frame = wazuh_payload_to_frame(json.loads(json.dumps(payload)))

        self.assertEqual(len(frame), 1)
        self.assertEqual(frame.iloc[0]["EventType"], "AUTH_FAILURE")
        self.assertEqual(frame.iloc[0]["Account"], "admin")
        self.assertEqual(frame.iloc[0]["RemoteIP"], "203.0.113.90")

    def test_wazuh_audit_keys_become_config_and_privileged_events(self):
        payload = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "timestamp": "2026-07-14T15:08:00Z",
                            "agent": {"name": "IOT-GW-01", "ip": "10.10.30.15"},
                            "predecoder": {"program_name": "shadowvault-audit"},
                            "data": {
                                "audit": {
                                    "key": "shadowvault_audit_config",
                                    "acct": "operator",
                                    "success": "yes",
                                    "file": {
                                        "name": "/etc/audit/rules.d/30-shadowvault.rules"
                                    },
                                }
                            },
                            "full_log": "Decoded audit configuration event",
                        }
                    },
                    {
                        "_source": {
                            "timestamp": "2026-07-14T15:10:00Z",
                            "agent": {"name": "IOT-GW-01", "ip": "10.10.30.15"},
                            "predecoder": {"program_name": "shadowvault-audit"},
                            "data": {
                                "audit": {
                                    "key": "shadowvault_privileged",
                                    "acct": "operator",
                                    "success": "yes",
                                    "exe": "/usr/bin/sudo",
                                }
                            },
                            "full_log": "Decoded privileged execution event",
                        }
                    },
                ]
            }
        }

        frame = wazuh_payload_to_frame(payload)

        self.assertEqual(frame["EventType"].tolist(), ["CONFIG_CHANGE", "PRIVILEGED_EXEC"])
        self.assertEqual(frame["Account"].tolist(), ["operator", "operator"])
        self.assertEqual(
            frame["Path"].tolist(),
            ["/etc/audit/rules.d/30-shadowvault.rules", "/usr/bin/sudo"],
        )

    def test_yocto_layer_contains_image_audit_and_forwarding_policy(self):
        layer = PROJECT_DIR / "meta-shadowvault"
        image_recipe = (layer / "recipes-core/images/shadowvault-soc-image.bb").read_text()
        audit_rules = (
            layer
            / "recipes-security/shadowvault-telemetry/files/30-shadowvault.rules"
        ).read_text()
        forwarder = (
            layer
            / "recipes-security/shadowvault-telemetry/files/90-shadowvault-forward.conf"
        ).read_text()

        self.assertIn("audit", image_recipe)
        self.assertIn("rsyslog", image_recipe)
        self.assertIn("shadowvault_audit_config", audit_rules)
        self.assertIn('type="omfwd"', forwarder)
        self.assertIn("@SHADOWVAULT_LOG_HOST@", forwarder)


if __name__ == "__main__":
    unittest.main()
