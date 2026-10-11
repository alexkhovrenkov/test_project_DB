"""
test_experiments.py - runs every tutorial example and every security experiment.

examples/*.sql and experiments/*.sql are executable documentation: each step
states what it expects ("-- @expect ...") and sqlrunner compares that with
what MariaDB really answers. A single mismatching step fails the test and the
step-by-step output is shown, so the README can never drift from reality.
"""

from pathlib import Path

import pytest

from sqlrunner import run_script

PROJECT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted((PROJECT / "examples").glob("*.sql")) + sorted((PROJECT / "experiments").glob("*.sql"))


def test_scripts_were_found():
    assert len(SCRIPTS) >= 16


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: f"{path.parent.name}/{path.name}")
def test_script_behaves_as_documented(script, harness):
    lines = []
    passed, failed = run_script(script, harness, quiet=True, out=lines.append)
    assert failed == 0, "\n".join(lines)
    assert passed > 5, "a script with almost no checked steps proves nothing"
