# SPDX-License-Identifier: GPL-3.0-or-later
import unittest

import run_safeyay_evals as evals


class EvalTests(unittest.TestCase):
    def test_ks_aur_scanner_manifest_summary_contains_only_severity_counts(self):
        findings = [
            {"severity": "critical", "title": "one", "assessment": "details"},
            {"severity": "high", "title": "two", "assessment": "details"},
            {"severity": "high", "title": "three", "assessment": "details"},
            {"severity": "low", "title": "four", "assessment": "details"},
        ]

        self.assertEqual(evals.finding_counts_by_severity(findings), {
            "critical": 1,
            "high": 2,
            "medium": 0,
            "low": 1,
            "info": 0,
        })


if __name__ == "__main__":
    unittest.main()
