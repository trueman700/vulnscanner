import unittest
from scanner.utils.scanner import clean_version, get_cpe, fetch_cves

class TestScannerUtils(unittest.TestCase):
    def test_clean_version(self):
        self.assertEqual(clean_version("1.2.3 (beta)"), "1.2.3")
        self.assertEqual(clean_version("2.0.1"), "2.0.1")
        self.assertEqual(clean_version(""), "")

    def test_get_cpe(self):
        self.assertEqual(get_cpe("http", "2.4.49"), "cpe:2.3:a:*:apache:http_server:2.4.49")
        self.assertEqual(get_cpe("ssh", "8.2"), "cpe:2.3:a:*:ssh:8.2")

    def test_fetch_cves(self):
        result = fetch_cves("http", "2.4.49")
        self.assertIn("result", result)
        self.assertIn("CVE_Items", result["result"])

if __name__ == '__main__':
    unittest.main()
