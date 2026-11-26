#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""aurora-fidod exits EX_CONFIG for a start that cannot succeed, and the unit
does not restart on that status."""
import configparser
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from aurora_fido import daemon  # noqa: E402

UNIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aurora-fido.service")


class StartFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = os.path.join(self.tmp.name, "aurora-fido.conf")

    def tearDown(self):
        self.tmp.cleanup()

    def main(self, *args):
        argv = ["--config", self.config, "--state-dir", self.tmp.name,
                "--run-dir", self.tmp.name, *args]
        with self.assertLogs("aurora-fido", level="ERROR") as logs, \
                mock.patch.object(daemon.os, "geteuid", return_value=0):
            rc = daemon.main(argv)
        return rc, "\n".join(logs.output)

    def test_not_root_is_a_configuration_failure(self):
        with mock.patch.object(daemon.os, "geteuid", return_value=1000), \
                self.assertLogs("aurora-fido", level="ERROR"):
            self.assertEqual(daemon.main(["--config", self.config]), daemon.EXIT_CONFIG)

    def test_a_refused_key_store_is_a_configuration_failure(self):
        with open(self.config, "w") as f:
            f.write("[keys]\nstore = sealed\n")
        rc, out = self.main()
        self.assertEqual(rc, daemon.EXIT_CONFIG)
        self.assertIn("no longer supported", out)

    def test_no_sep_key_is_a_configuration_failure(self):
        with mock.patch.object(daemon, "open_backend",
                               side_effect=daemon.BackendError("/dev/sep-key not present")):
            rc, out = self.main()
        self.assertEqual(rc, daemon.EXIT_CONFIG)
        self.assertIn("/dev/sep-key not present", out)

    def test_the_unit_does_not_restart_on_it(self):
        unit = configparser.ConfigParser(strict=False, interpolation=None)
        unit.optionxform = str
        unit.read(UNIT)
        self.assertEqual(unit.get("Service", "Restart"), "on-failure")
        self.assertIn(str(daemon.EXIT_CONFIG),
                      unit.get("Service", "RestartPreventExitStatus").split())


if __name__ == "__main__":
    unittest.main()
