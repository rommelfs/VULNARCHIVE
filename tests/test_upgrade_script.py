from pathlib import Path
import importlib.util
import stat
import subprocess
import tempfile
import unittest


class UpgradeScriptTests(unittest.TestCase):
    def test_upgrade_script_is_executable_and_contains_safety_steps(self):
        script = Path(__file__).parents[1] / "deploy" / "upgrade.sh"
        content = script.read_text(encoding="utf-8")
        self.assertTrue(script.stat().st_mode & stat.S_IXUSR)
        for expected in (
            "set -Eeuo pipefail",
            "UPGRADE_SCRIPT_VERSION=5",
            "flock -n",
            "git pull --ff-only",
            "clean_build_artifacts",
            "git ls-files -- \"$path\"",
            "rm -rf -- \"$path\"",
            "git diff --quiet",
            "git diff --cached --quiet",
            "python\" -m unittest",
            "source.backup(target)",
            "pip install --no-deps --force-reinstall",
            "systemctl daemon-reload",
            "plan-auto --limit 1",
            "curl --silent --fail --max-time 2",
            "configured_source_ids",
            "WARNING: VA_SOURCES is absent",
            "Service restart applied environment changes",
            "Checking private review service",
            "private review service is not reachable",
        ):
            self.assertIn(expected, content)

    def test_documentation_uses_the_upgrade_script(self):
        deployment = (Path(__file__).parents[1] / "DEPLOYMENT.md").read_text(encoding="utf-8")
        self.assertIn("sudo /opt/vulnarchive/deploy/upgrade.sh", deployment)
        self.assertIn("--no-pull", deployment)
        self.assertIn("rm -rf -- build src/fd_sightings.egg-info", deployment)
        self.assertIn("VULNARCHIVE upgrade script 5", deployment)
        self.assertIn("sudo /opt/vulnarchive/deploy/install-apache-config.sh", deployment)

    def test_apache_installer_backs_up_validates_and_reloads(self):
        script = Path(__file__).parents[1] / "deploy" / "install-apache-config.sh"
        content = script.read_text(encoding="utf-8")
        self.assertTrue(script.stat().st_mode & stat.S_IXUSR)
        for expected in (
            "set -Eeuo pipefail", "cp -a --", "apachectl configtest",
            "systemctl reload apache2", "trap restore EXIT",
            "VULNARCHIVE_APACHE_SITE", "apachectl -S", "sites-enabled",
        ):
            self.assertIn(expected, content)

    def test_package_versions_are_consistent(self):
        root = Path(__file__).parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        package = (root / "src/fd_sightings/__init__.py").read_text(encoding="utf-8")
        self.assertIn('version = "0.3.0"', pyproject)
        self.assertIn('__version__ = "0.3.0"', package)

    def test_upgrade_rejects_invalid_target_arguments_before_deployment(self):
        script = Path(__file__).parents[1] / "deploy" / "upgrade.sh"
        for args in (("--ref",), ("--ref", "--no-pull"),
                     ("--no-pull", "--ref", "work"),
                     ("--ref", "work", "--no-pull"),
                     ("--ref", "work", "--ref", "main"),
                     ("--no-pull", "unexpected")):
            with self.subTest(args=args):
                result = subprocess.run(["bash", str(script), *args], capture_output=True)
                self.assertEqual(result.returncode, 2)

    def test_installed_source_verification_detects_stale_or_missing_code(self):
        script = Path(__file__).parents[1] / "deploy" / "verify-installed-package.py"
        spec = importlib.util.spec_from_file_location("verify_installed", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            source, installed = Path(directory) / "source", Path(directory) / "installed"
            source.mkdir()
            installed.mkdir()
            for root in (source, installed):
                (root / "cli.py").write_text("new code\n")
            module.verify(source, installed)
            (installed / "cli.py").write_text("old code\n")
            with self.assertRaisesRegex(RuntimeError, "source differs: cli.py"):
                module.verify(source, installed)
            (installed / "cli.py").unlink()
            with self.assertRaisesRegex(RuntimeError, "file list differs"):
                module.verify(source, installed)


if __name__ == "__main__":
    unittest.main()
