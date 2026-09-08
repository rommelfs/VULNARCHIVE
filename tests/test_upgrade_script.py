from pathlib import Path
import stat
import unittest


class UpgradeScriptTests(unittest.TestCase):
    def test_upgrade_script_is_executable_and_contains_safety_steps(self):
        script = Path(__file__).parents[1] / "deploy" / "upgrade.sh"
        content = script.read_text(encoding="utf-8")
        self.assertTrue(script.stat().st_mode & stat.S_IXUSR)
        for expected in (
            "set -Eeuo pipefail",
            "UPGRADE_SCRIPT_VERSION=4",
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
        self.assertIn("VULNARCHIVE upgrade script 4", deployment)
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


if __name__ == "__main__":
    unittest.main()
