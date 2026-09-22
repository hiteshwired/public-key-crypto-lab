# test_task2_smoke.py
# smoke test for task2.py's generator-tampering demo
# Validates: Requirements 3.5
# per the design's testing strategy, this is a smoke-level check that all
# three alpha cases (alpha = 1, alpha = q, alpha = q - 1) run without error
# and print the expected explanatory text

import os
import subprocess
import sys

# path to task2.py at the project root, one level up from this tests/ folder
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASK2_PATH = os.path.join(PROJECT_ROOT, "task2.py")


def test_task2_generator_tampering_demo_runs_and_prints_expected_text():
    result = subprocess.run(
        [sys.executable, TASK2_PATH],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    # task2.py should run to completion without raising/asserting an error
    assert result.returncode == 0

    output = result.stdout

    # section header for the generator-tampering demo
    assert "Generator-Tampering Demo" in output

    # pass 1: alpha = 1
    assert "Pass 1: alpha = 1" in output
    assert "always 1" in output

    # pass 2: alpha = q
    assert "Pass 2: alpha = 37" in output
    assert "always 0 mod q" in output

    # pass 3: alpha = q - 1
    assert "Pass 3: alpha = 36" in output
    assert "two possible" in output
