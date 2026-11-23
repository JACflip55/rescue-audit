import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rescue_audit  # noqa: E402

FAKE_AWS_KEY = "AKIA" + "Q" * 16  # assembled at runtime so no key-shaped string sits in the repo


class AuditTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def checks(self):
        return {f.check for f in rescue_audit.audit(self.root)}

    def healthy(self):
        self.write("README.md", "# app\n")
        self.write(".gitignore", ".env\n")
        self.write(".github/workflows/ci.yml", "on: push\n")
        self.write("app.py", "def add(a, b):\n    return a + b\n")
        self.write("tests/test_app.py", "def test_add():\n    assert True\n")
        self.write("requirements.txt", "flask==3.0.0\n")

    def test_healthy_project_is_clean(self):
        self.healthy()
        self.assertEqual(rescue_audit.audit(self.root), [])

    def test_empty_directory_only_lacks_readme(self):
        self.assertEqual(self.checks(), {"no-readme"})

    def test_bare_project_reports_missing_basics(self):
        self.write("app.py", "print('hi')\n")
        self.assertEqual(self.checks(), {"no-tests", "no-ci", "no-readme", "no-gitignore"})

    def test_secret_is_reported_with_line_number(self):
        self.healthy()
        self.write("config.py", f"REGION = 'us-east-1'\nKEY = '{FAKE_AWS_KEY}'\n")
        found = [f for f in rescue_audit.audit(self.root) if f.check == "secret"]
        self.assertEqual([(f.path, f.line, f.severity) for f in found], [("config.py", 2, "high")])

    def test_placeholder_credentials_are_ignored(self):
        self.healthy()
        self.write("config.py", "api_key = 'your-api-key-goes-here'\npassword = os.environ['DB_PASSWORD']\n")
        self.assertNotIn("secret", self.checks())

    def test_hardcoded_password_is_reported(self):
        self.healthy()
        self.write("db.py", "password = 'hunter2hunter2hunter2'\n")
        self.assertIn("secret", self.checks())

    def test_env_file_flagged_but_example_is_not(self):
        self.healthy()
        self.write(".env.example", "TOKEN=\n")
        self.assertNotIn("env-file", self.checks())
        self.write(".env", "TOKEN=abc\n")
        self.assertIn("env-file", self.checks())

    def test_unpinned_requirements(self):
        self.healthy()
        self.write("requirements.txt", "flask==3.0.0\nrequests\nnumpy>=1.20\n# comment\n")
        found = [f for f in rescue_audit.audit(self.root) if f.check == "unpinned-deps"]
        self.assertEqual(len(found), 1)
        self.assertIn("2 dependencies", found[0].message)

    def test_package_json_without_lockfile(self):
        self.healthy()
        self.write("web/package.json", "{}\n")
        self.assertIn("no-lockfile", self.checks())
        self.write("web/package-lock.json", "{}\n")
        self.assertNotIn("no-lockfile", self.checks())

    def test_debug_and_swallowed_errors(self):
        self.healthy()
        self.write("server.py", "DEBUG = True\ntry:\n    run()\nexcept:\n    pass\n")
        self.write("web/app.js", "try { go() } catch (e) {}\n")
        found = rescue_audit.audit(self.root)
        self.assertEqual(sorted((f.check, f.path, f.line) for f in found),
                         [("debug", "server.py", 1), ("swallowed-error", "server.py", 4), ("swallowed-error", "web/app.js", 1)])

    def test_skipped_directories_are_not_scanned(self):
        self.healthy()
        self.write("node_modules/pkg/index.js", f"const k = '{FAKE_AWS_KEY}'\n")
        self.assertEqual(rescue_audit.audit(self.root), [])

    def test_minified_bundles_are_not_reviewed(self):
        self.healthy()
        self.write("static/bundle.js", "try{a()}catch(e){}" * 600)
        self.write("static/lib.min.js", "try{a()}catch(e){}\n")
        self.assertEqual(rescue_audit.audit(self.root), [])

    def test_long_file_and_todo_debt(self):
        self.healthy()
        self.write("big.py", "x = 1\n" * 900)
        self.write("notes.py", "# TODO fix\n" * 25)
        self.assertEqual(self.checks(), {"long-file", "todo-debt"})

    def test_findings_sorted_by_severity(self):
        self.write("app.py", "DEBUG = True\n")
        severities = [f.severity for f in rescue_audit.audit(self.root)]
        self.assertEqual(severities, sorted(severities, key=rescue_audit.SEVERITY_ORDER.get))


class CliTest(unittest.TestCase):
    def run_cli(self, *args):
        buf = StringIO()
        with redirect_stdout(buf):
            code = rescue_audit.main(list(args))
        return code, buf.getvalue()

    def test_json_output_and_strict_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("x = 1\n")
            code, out = self.run_cli(tmp, "--json", "--strict")
            self.assertEqual(code, 1)
            self.assertIn("no-tests", {f["check"] for f in json.loads(out)})
            code, _ = self.run_cli(tmp)
            self.assertEqual(code, 0)

    def test_missing_directory_returns_2(self):
        code, _ = self.run_cli("/no/such/dir/for/rescue-audit")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
