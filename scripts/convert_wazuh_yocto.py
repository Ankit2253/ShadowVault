"""Convert a Wazuh Indexer JSON export to ShadowVault Yocto CSV telemetry."""

import argparse
import json
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from yocto_adapter import wazuh_payload_to_frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Wazuh Indexer JSON export")
    parser.add_argument("output", type=Path, help="Destination Yocto CSV")
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    frame = wazuh_payload_to_frame(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False, lineterminator="\n")
    print(f"Wrote {len(frame)} normalized Yocto events to {args.output}")


if __name__ == "__main__":
    main()
