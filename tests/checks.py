"""
checks.py - two tiny helpers used by all test files.

  expect_allowed(description, action)
      PASS if action() runs without an error.

  expect_blocked(description, action, expected_code, expected_text="")
      PASS only if action() fails with exactly that MariaDB/client error code
      (and the message contains expected_text). Checking the code matters: a
      test should not "pass" because of some unrelated error like a typo.
"""

import sys
from pathlib import Path

# Make "from database import ..." work from the tests folder.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import pymysql

results = []   # one True/False per check


def record(passed, description, detail=""):
    results.append(passed)
    print(f"[{'PASS' if passed else 'FAIL'}] {description}")
    if detail:
        print(f"       {detail}")


def expect_allowed(description, action):
    try:
        action()
        record(True, description)
    except (pymysql.MySQLError, AssertionError) as error:
        record(False, description, f"expected success but got: {error!r}")


def expect_blocked(description, action, expected_code, expected_text=""):
    try:
        action()
        record(False, description, "it was ALLOWED, but it should have been blocked")
    except pymysql.MySQLError as error:
        code, message = error.args[0], str(error.args[1])
        if code == expected_code and expected_text in message:
            record(True, description, f"error {code}: {message}")
        else:
            record(False, description,
                   f"blocked, but with the wrong error: {code}: {message}")


def summary():
    """Print the totals. Returns the exit code: 0 if everything passed."""
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1
