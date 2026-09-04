import importlib.util
import unittest
from email.message import Message
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_bcp03", ROOT / "deploy" / "verify-bcp03.py")
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)


class FakeHTTP:
    def __init__(self, content_type="text/plain; charset=utf-8", body=b"GCVE: https://vuln.freearchive.org\n"):
        self.content_type = content_type
        self.body = body

    def request(self, path):
        headers = Message()
        headers["Content-Type"] = self.content_type
        return 200, self.body, headers


class SecurityTxtTests(unittest.TestCase):
    def test_public_gcve_base_is_advertised(self):
        text = (ROOT / "deploy" / "security.txt").read_text(encoding="utf-8")
        self.assertEqual(text, "GCVE: https://vuln.freearchive.org\n")
        self.assertEqual(VERIFY.gcve_base(FakeHTTP()), "https://vuln.freearchive.org")

    def test_gcve_base_rejects_wrong_content_type(self):
        with self.assertRaisesRegex(VERIFY.CheckFailure, "Content-Type"):
            VERIFY.gcve_base(FakeHTTP(content_type="text/plain"))

    def test_apache_serves_security_txt_without_proxying(self):
        config = (ROOT / "deploy" / "apache-vuln.freearchive.org.conf").read_text(encoding="utf-8")
        self.assertIn('ProxyPass "/.well-known/security.txt" "!"', config)
        self.assertIn('Alias "/.well-known/security.txt" "/opt/vulnarchive/deploy/security.txt"', config)
        self.assertIn('Header always set Content-Type "text/plain; charset=utf-8"', config)


if __name__ == "__main__":
    unittest.main()
