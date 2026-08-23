"""Run the complete ShadowVault workflow with one command."""

import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
STEPS = [
    ("Generate synthetic logs", "src/log_generator.py"),
    ("Detect and correlate", "src/correlation_engine.py"),
    ("Evaluate detections", "src/evaluate.py"),
    ("Generate incident report", "src/report_generator.py"),
]


def main():
    for label, script in STEPS:
        print(f"\n[{label}]")
        subprocess.run([sys.executable, str(PROJECT_DIR / script)], check=True)
    print("\nShadowVault pipeline completed successfully.")
    print("Launch the dashboard with: streamlit run dashboard.py")


if __name__ == "__main__":
    main()
