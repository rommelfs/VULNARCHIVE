from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LicenseTests(unittest.TestCase):
    def test_agpl_and_copyright_notices_are_shipped(self):
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", license_text)
        self.assertIn("Version 3, 19 November 2007", license_text)
        self.assertIn("Remote Network Interaction", license_text)
        self.assertIn("Computer Incident Response Center Luxembourg (CIRCL)", notice)
        self.assertIn("https://circl.lu/", notice)
        self.assertIn("Sascha Rommelfangen", notice)
        self.assertIn("https://github.com/rommelfs", notice)
        self.assertIn('license = {file = "LICENSE"}', metadata)


if __name__ == "__main__":
    unittest.main()
