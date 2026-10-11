"""
run_all.py - run every security test.

Run:  python tests/run_all.py
"""

import sys

import test_authentication
import test_permissions
import test_tls
from checks import summary

test_permissions.run()
test_authentication.run()
test_tls.run()
sys.exit(summary())
