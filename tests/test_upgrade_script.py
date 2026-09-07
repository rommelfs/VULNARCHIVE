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
            "flock -n",
            "git pull --ff-only",
            "git status --porcelain",
            "python\" -m unittest",
            "source.backup(target)",
            "pip install --no-deps --force-reinstall",
            "systemctl daemon-reload",
            "plan-auto --limit 1",
            "curl --silent --show-error --fail",
        ):
            self.assertIn(expected, content)

    def test_documentation_uses_the_upgrade_script(self):
        deployment = (Path(__file__).parents[1] / "DEPLOYMENT.md").read_text(encoding="utf-8")
        self.assertIn("sudo /opt/vulnarchive/deploy/upgrade.sh", deployment)
        self.assertIn("--no-pull", deployment)


if __name__ == "__main__":
    unittest.main()
