# SPDX-License-Identifier: GPL-3.0-or-later
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

import safeyay_scanner as scanner


class ScannerTests(unittest.TestCase):
    def backend_result(self):
        return {"suspicious": False, "summary": "clean", "findings": []}

    def test_finds_pkgbuild_and_install_script(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PKGBUILD").write_text("pkgname=demo")
            (root / "demo.install").write_text("post_install() { :; }")
            names = {path.name for path in scanner.candidate_files([directory])}
            self.assertEqual(names, {"PKGBUILD", "demo.install"})

    def test_finds_referenced_npm_and_patch_files_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PKGBUILD").write_text("source=(fix.patch package.json install.js archive.tar.gz)")
            for name in ("fix.patch", "package.json", "install.js", "unreferenced.js", "archive.tar.gz"):
                (root / name).write_text("fixture")
            names = {path.name for path in scanner.candidate_files([root / "PKGBUILD"])}
            self.assertEqual(names, {"PKGBUILD", "fix.patch", "package.json", "install.js"})

    def test_finds_referenced_security_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PKGBUILD").write_text("source=(limits.conf app.desktop daemon.service)")
            for name in ("limits.conf", "app.desktop", "daemon.service"):
                (root / name).write_text("fixture")
            names = {path.name for path in scanner.candidate_files([root])}
            self.assertEqual(names, {"PKGBUILD", "limits.conf", "app.desktop", "daemon.service"})

    def test_finds_referenced_extensionless_text_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PKGBUILD").write_text("source=(safeyay payload)\npackage() { install safeyay /usr/bin/safeyay; }")
            (root / "safeyay").write_text("#!/usr/bin/env bash\nexec yay \"$@\"\n")
            (root / "payload").write_bytes(b"\x7fELF\0binary")
            names = {path.name for path in scanner.candidate_files([root / "PKGBUILD"])}
            self.assertEqual(names, {"PKGBUILD", "safeyay"})

    def test_groups_split_packages_once_and_separate_pkgbuilds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            one, two = root / "one", root / "two"
            one.mkdir(); two.mkdir()
            (one / "PKGBUILD").write_text("pkgbase=one")
            (one / "one.install").write_text("")
            (two / "PKGBUILD").write_text("pkgname=two")
            groups = scanner.package_groups([str(one / "PKGBUILD"), str(one / "one.install"), str(two / "PKGBUILD")])
            self.assertEqual([[path.name for path in group] for group in groups], [["PKGBUILD", "one.install"], ["PKGBUILD"]])

    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", side_effect=lambda name: "/usr/bin/aur-scan" if name == "aur-scan" else None)
    def test_ks_aur_scanner_runs_before_independent_llm_review(self, _which, run, analyze):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({"package_name": "demo", "findings": []})
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 0)
        run.assert_called_once_with(
            ["/usr/bin/aur-scan", "scan", "-f", "json", "-q", directory],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(analyze.call_count, 1)
        self.assertNotIn("aur-scan", analyze.call_args.args[0])

    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner.shutil, "which", return_value=None)
    def test_ks_aur_scanner_absence_is_announced_not_silent(self, _which, _analyze):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]), \
                    patch("sys.stderr") as stderr:
                self.assertEqual(scanner.main(), 0)
            output = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("ks-aur-scanner (aur-scan) not found on PATH", output)
        self.assertIn("ClamAV not found on PATH", output)

    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", side_effect=lambda name: "/usr/bin/aur-scan" if name == "aur-scan" else None)
    def test_ks_aur_scanner_detection_is_announced(self, _which, run, _analyze):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({"package_name": "demo", "findings": []})
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]), \
                    patch("sys.stderr") as stderr:
                self.assertEqual(scanner.main(), 0)
            output = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("ks-aur-scanner detected (/usr/bin/aur-scan)", output)

    @patch.object(scanner, "confirm", return_value=False)
    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", side_effect=lambda name: "/usr/bin/aur-scan" if name == "aur-scan" else None)
    def test_ks_aur_scanner_critical_finding_still_runs_llm_and_prompts(self, _which, run, analyze, confirm):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({
            "package_name": "demo",
            "findings": [{"id": "PRIV-002", "severity": "critical", "title": "SUID bit", "location": {}}],
        })
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 3)
        analyze.assert_called_once()
        confirm.assert_called_once()

    @patch.object(scanner, "confirm", return_value=False)
    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", side_effect=lambda name: "/usr/bin/aur-scan" if name == "aur-scan" else None)
    def test_ks_aur_scanner_non_critical_finding_still_runs_llm_and_prompts(self, _which, run, analyze, confirm):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({
            "package_name": "demo",
            "findings": [{"id": "HIDDEN-001", "severity": "high", "title": "Hidden file", "location": {}}],
        })
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 3)
        analyze.assert_called_once()
        confirm.assert_called_once()

    @patch.object(scanner, "analyze")
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", side_effect=lambda name: "/usr/bin/aur-scan" if name == "aur-scan" else None)
    def test_ks_aur_scanner_failure_prevents_llm_review(self, _which, run, analyze):
        run.return_value.returncode = 2
        run.return_value.stdout = ""
        run.return_value.stderr = "boom"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 2)
        analyze.assert_not_called()

    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", side_effect=lambda name: "/usr/bin/clamdscan" if name == "clamdscan" else None)
    def test_clamav_command_prefers_running_daemon(self, _which, run):
        run.return_value.returncode = 0
        self.assertEqual(scanner.clamav_command(), ["/usr/bin/clamdscan", "--fdpass"])

    @patch.object(scanner.shutil, "which")
    def test_clamav_command_falls_back_to_clamscan_when_daemon_unreachable(self, which):
        which.side_effect = lambda name: {"clamdscan": "/usr/bin/clamdscan", "clamscan": "/usr/bin/clamscan"}.get(name)
        with patch.object(scanner.subprocess, "run") as run:
            run.return_value.returncode = 2
            self.assertEqual(scanner.clamav_command(), ["/usr/bin/clamscan"])

    @patch.object(scanner.shutil, "which", return_value=None)
    def test_clamav_command_returns_none_when_absent(self, _which):
        self.assertIsNone(scanner.clamav_command())

    @patch.object(scanner.subprocess, "run")
    def test_run_clamav_scan_returns_infected_lines(self, run):
        run.return_value.returncode = 1
        run.return_value.stdout = "/tmp/pkg/evil.sh: Eicar-Signature FOUND\n"
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            result = scanner.run_clamav_scan(["/usr/bin/clamscan"], [path], "demo")
        self.assertEqual(result, ["/tmp/pkg/evil.sh: Eicar-Signature FOUND"])

    @patch.object(scanner.subprocess, "run")
    def test_run_clamav_scan_returns_empty_when_clean(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            result = scanner.run_clamav_scan(["/usr/bin/clamscan"], [path], "demo")
        self.assertEqual(result, [])

    @patch.object(scanner.subprocess, "run")
    def test_run_clamav_scan_raises_on_error_exit_code(self, run):
        run.return_value.returncode = 2
        run.return_value.stdout = ""
        run.return_value.stderr = "LibClamAV Error: no database"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with self.assertRaises(RuntimeError):
                scanner.run_clamav_scan(["/usr/bin/clamscan"], [path], "demo")

    @patch.object(scanner, "analyze")
    @patch.object(scanner, "clamav_command", return_value=["/usr/bin/clamscan"])
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", return_value=None)
    def test_clamav_infection_hard_stops_before_ks_aur_scanner_and_llm(self, _which, run, _clamav_command, analyze):
        run.return_value.returncode = 1
        run.return_value.stdout = "PKGBUILD: Eicar-Signature FOUND\n"
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 3)
        analyze.assert_not_called()
        run.assert_called_once()

    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner, "clamav_command", return_value=["/usr/bin/clamscan"])
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", return_value=None)
    def test_clamav_clean_continues_to_llm(self, _which, run, _clamav_command, analyze):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 0)
        analyze.assert_called_once()

    @patch.object(scanner, "analyze")
    @patch.object(scanner, "clamav_command", return_value=["/usr/bin/clamscan"])
    @patch.object(scanner.subprocess, "run")
    @patch.object(scanner.shutil, "which", return_value=None)
    def test_clamav_failure_fails_closed(self, _which, run, _clamav_command, analyze):
        run.return_value.returncode = 2
        run.return_value.stdout = ""
        run.return_value.stderr = "no database"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner, "BACKEND", "codex"), patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 2)
        analyze.assert_not_called()

    @patch.object(scanner.shutil, "which", return_value=None)
    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner, "ensure_ollama_running", return_value="existing")
    def test_clean_review_succeeds(self, _ollama, _analyze, _which):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 0)

    @patch.object(scanner.shutil, "which", return_value=None)
    @patch.object(scanner, "confirm", return_value=False)
    @patch.object(scanner, "analyze", return_value={"suspicious": True, "summary": "bad", "findings": []})
    @patch.object(scanner, "ensure_ollama_running", return_value="existing")
    def test_suspicious_review_is_rejected_by_default(self, _ollama, _analyze, _confirm, _which):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            with patch.object(scanner.sys, "argv", ["scanner", str(path)]):
                self.assertEqual(scanner.main(), 3)

    @patch.object(scanner.shutil, "which", return_value=None)
    @patch.object(scanner.time, "perf_counter", side_effect=[10.0, 11.25, 20.0, 22.5])
    @patch.object(scanner, "analyze", return_value={"suspicious": False, "summary": "normal", "findings": []})
    @patch.object(scanner, "ensure_ollama_running", return_value="existing")
    def test_reports_per_package_and_running_review_time(self, _ollama, _analyze, _clock, _which):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for name in ("one", "two"):
                package = root / name
                package.mkdir()
                path = package / "PKGBUILD"
                path.write_text(f"pkgname={name}")
                paths.append(str(path))
            with patch.object(scanner.sys, "argv", ["scanner", *paths]), patch("sys.stderr") as stderr:
                self.assertEqual(scanner.main(), 0)
            output = "".join(call.args[0] for call in stderr.write.call_args_list)
            self.assertIn("Review time for one: 1.25s (running total: 1.25s)", output)
            self.assertIn("Review time for two: 2.50s (running total: 3.75s)", output)

    @patch.object(scanner, "ollama_running", return_value=True)
    def test_reuses_existing_ollama(self, _running):
        self.assertEqual(scanner.ensure_ollama_running(), "existing")

    @patch.object(scanner.atexit, "register")
    @patch.object(scanner.subprocess, "Popen")
    @patch.object(scanner, "ollama_running", side_effect=[False, False, True])
    def test_starts_and_records_owned_ollama(self, _running, popen, register):
        process = popen.return_value
        process.pid = 4242
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(scanner.os.environ, {"SAFEYAY_OLLAMA_STATE_DIR": directory}):
                self.assertEqual(scanner.ensure_ollama_running(), "started")
            self.assertEqual((Path(directory) / "ollama.pid").read_text(), "4242\n")
        register.assert_called_once_with(scanner.stop_owned_ollama)
        scanner.OWNED_OLLAMA_PROCESS = None
        scanner.OWNED_OLLAMA_PID_FILE = None

    @patch.dict(scanner.os.environ, {"SAFEYAY_WEB_SEARCH": "0"})
    @patch.object(scanner.urllib.request, "urlopen")
    def test_ollama_response_is_parsed_and_raw_output_logged(self, urlopen):
        payload = {"message": {"content": json.dumps({
            "suspicious": False, "summary": "clean", "findings": []
        }), "thinking": "reviewed it"}}
        response = urlopen.return_value.__enter__.return_value
        response.read.return_value = json.dumps(payload).encode()
        with tempfile.TemporaryDirectory() as directory:
            raw_path = Path(directory) / "raw.json"
            result = scanner.analyze("pkgname=demo", raw_path)
            self.assertFalse(result["suspicious"])
            self.assertEqual(json.loads(raw_path.read_text()), payload)

    @patch.object(scanner, "http_json")
    def test_openai_responses_backend(self, http_json):
        result = self.backend_result()
        http_json.return_value = ({"output_text": json.dumps(result)}, b"raw")
        with patch.object(scanner, "BACKEND", "openai"), patch.object(scanner, "MODEL", "test"), patch.dict(scanner.CONFIG, {"base_url": "https://api.openai.com/v1", "api_key_env": "TEST_KEY"}, clear=False), patch.dict(scanner.os.environ, {"TEST_KEY": "secret"}):
            self.assertEqual(scanner.invoke_backend("system", "user", None), result)
        self.assertEqual(http_json.call_args.args[2]["Authorization"], "Bearer secret")

    @patch.object(scanner, "http_json")
    def test_anthropic_backend(self, http_json):
        result = self.backend_result()
        http_json.return_value = ({"content": [{"type": "text", "text": json.dumps(result)}]}, b"raw")
        with patch.object(scanner, "BACKEND", "anthropic"), patch.object(scanner, "MODEL", "claude-sonnet-5"), patch.dict(scanner.CONFIG, {"base_url": "https://api.anthropic.com/v1", "api_key_env": "TEST_KEY"}, clear=False), patch.dict(scanner.os.environ, {"TEST_KEY": "secret"}):
            self.assertEqual(scanner.invoke_backend("system", "user", None), result)
        self.assertEqual(http_json.call_args.args[2]["x-api-key"], "secret")

    @patch.object(scanner, "http_json")
    def test_openai_compatible_custom_auth_header(self, http_json):
        result = self.backend_result()
        http_json.return_value = ({"choices": [{"message": {"content": json.dumps(result)}}]}, b"raw")
        config = {"base_url": "https://gateway.example/v1", "api_key_env": "TEST_KEY", "api_key_header": "api-key", "api_key_prefix": ""}
        with patch.object(scanner, "BACKEND", "openai_compatible"), patch.object(scanner, "MODEL", "deployment"), patch.dict(scanner.CONFIG, config, clear=False), patch.dict(scanner.os.environ, {"TEST_KEY": "secret"}):
            self.assertEqual(scanner.invoke_backend("system", "user", None), result)
        self.assertEqual(http_json.call_args.args[2], {"api-key": "secret"})

    @patch.object(scanner, "http_json")
    def test_gemini_backend(self, http_json):
        result = self.backend_result()
        http_json.return_value = ({"candidates": [{"content": {"parts": [{"text": json.dumps(result)}]}}]}, b"raw")
        with patch.object(scanner, "BACKEND", "gemini"), patch.object(scanner, "MODEL", "gemini-test"), patch.dict(scanner.CONFIG, {"base_url": "https://generativelanguage.googleapis.com/v1beta", "api_key_env": "TEST_KEY"}, clear=False), patch.dict(scanner.os.environ, {"TEST_KEY": "secret"}):
            self.assertEqual(scanner.invoke_backend("system", "user", None), result)
        self.assertEqual(http_json.call_args.args[2]["x-goog-api-key"], "secret")

    @patch.object(scanner, "run_command")
    def test_claude_cli_backend(self, run_command):
        result = self.backend_result()
        run_command.return_value = {"structured_output": result}
        with patch.object(scanner, "BACKEND", "claude"), patch.object(scanner, "MODEL", "sonnet"):
            self.assertEqual(scanner.invoke_backend("system", "user", None), result)
        command = run_command.call_args.args[0]
        self.assertIn("--no-session-persistence", command)
        self.assertIn("--json-schema", command)

    @patch.object(scanner, "run_command")
    def test_generic_command_backend_uses_argv(self, run_command):
        result = self.backend_result()
        run_command.return_value = result
        with patch.object(scanner, "BACKEND", "command"), patch.dict(scanner.CONFIG, {"command": ["reviewer", "--json"]}, clear=False):
            self.assertEqual(scanner.invoke_backend("system", "user", None), result)
        self.assertEqual(run_command.call_args.args[0], ["reviewer", "--json"])

    def test_loads_user_toml_and_environment_override(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('backend = "anthropic"\nmodel = "configured"\napi_key_env = "MY_KEY"\n')
            with patch.dict(scanner.os.environ, {"SAFEYAY_CONFIG": str(path), "SAFEYAY_MODEL": "overridden"}, clear=False):
                config = scanner.load_config()
            self.assertEqual(config["backend"], "anthropic")
            self.assertEqual(config["model"], "overridden")
            self.assertEqual(config["api_key_env"], "MY_KEY")

    def test_anthropic_default_is_sonnet_5(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('backend = "anthropic"\n')
            with patch.dict(scanner.os.environ, {"SAFEYAY_CONFIG": str(path)}, clear=True):
                config = scanner.load_config()
            self.assertEqual(config["model"], "claude-sonnet-5")

    def test_package_name_extraction_does_not_execute_shell(self):
        source = "pkgname=brave-bin\nprepare() { curl https://example.test; }"
        self.assertEqual(scanner.package_name(source), "brave-bin")

    def test_real_world_package_name_forms(self):
        self.assertEqual(scanner.package_name("pkgbase=joplin\npkgname=('joplin' 'joplin-desktop')"), "joplin")
        self.assertEqual(scanner.package_name("_projectname='ExpressLRS-Configurator'\npkgname=\"${_projectname,,}\""), "ExpressLRS-Configurator")

    def test_source_hosts_are_plain_sanitized_hostnames(self):
        source = "url=https://brave.com\nsource=(https://github.com/brave/release https://brave.com/x)"
        self.assertEqual(scanner.source_hosts(source), ["brave.com", "github.com"])

    def test_auxiliary_urls_do_not_pollute_provenance_identity(self):
        source = "===== PKGBUILD =====\npkgname=demo\nurl=https://github.com/owner/demo\n\n===== launcher.sh =====\ncurl https://unrelated.example/x"
        self.assertEqual(scanner.source_hosts(source), ["github.com"])
        self.assertEqual(scanner.source_urls(source), ["https://github.com/owner/demo"])

    def test_extracts_only_sanitized_github_repository_identity(self):
        source = "url=https://github.com/GloriousEggroll/proton-ge-custom/releases/download/v1/a.tar.gz\n# https://gitlab.com/other/repo"
        self.assertEqual(scanner.github_repositories(source), ["GloriousEggroll/proton-ge-custom"])

    def test_safely_expands_literal_url_variables_without_shell(self):
        source = "pkgname=maxautoclicker\npkgver=1.5.8\nsource=(https://github.com/mautosoft/$pkgname/releases/v$pkgver/file)\nevil=$(touch /tmp/nope)"
        self.assertEqual(scanner.github_repositories(source), ["mautosoft/maxautoclicker"])
        self.assertIn("$(touch /tmp/nope)", scanner.expand_simple_variables(source))

    def test_expands_underscored_project_name(self):
        source = "_projectname='ExpressLRS-Configurator'\nurl=https://github.com/ExpressLRS/$_projectname"
        self.assertEqual(scanner.github_repositories(source), ["ExpressLRS/ExpressLRS-Configurator"])

    def test_parses_brave_search_result_structure(self):
        page = b'''<div class="snippet" data-pos="0" data-type="web"><a href="https://github.com/owner/project"><div class="snippet-title x" title="Owner &amp; Project">x</div></a><div class="generic-snippet x"><div class="content x"><p>Official <b>source</b> repository</p></div></div></div>'''
        self.assertEqual(scanner.parse_brave_results(page), [{
            "title": "Owner & Project", "url": "https://github.com/owner/project", "snippet": "Official source repository"
        }])

    def test_parses_duckduckgo_redirect_result(self):
        page = b'''<div class="result results_links"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fgithub.com%2Fowner%2Fproject">Owner Project</a><a class="result__snippet">Official source repository</a></div>'''
        self.assertEqual(scanner.parse_duckduckgo_results(page), [{
            "title": "Owner Project", "url": "https://github.com/owner/project", "snippet": "Official source repository"
        }])

    def test_model_input_does_not_expose_fixture_directory_label(self):
        with tempfile.TemporaryDirectory(prefix="obvious-tampered-label-") as directory:
            path = Path(directory) / "PKGBUILD"
            path.write_text("pkgname=demo")
            model_input = scanner.read_sources([path])
            self.assertNotIn("obvious-tampered-label", model_input)
            self.assertIn("===== PKGBUILD =====", model_input)


if __name__ == "__main__":
    unittest.main()
