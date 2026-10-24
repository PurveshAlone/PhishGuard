import unittest
from analyzer import analyze_url, MAX_URL_LENGTH


class URLAnalyzerTests(unittest.TestCase):
    def test_rejects_empty_input(self):
        self.assertFalse(analyze_url("").get("valid"))

    def test_requires_http_scheme(self):
        self.assertFalse(analyze_url("javascript:alert(1)").get("valid"))
        self.assertFalse(analyze_url("example.com").get("valid"))

    def test_accepts_basic_https_url(self):
        result = analyze_url("https://example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["score"], 0)

    def test_http_adds_rule(self):
        result = analyze_url("http://example.com")
        self.assertTrue(any(rule["name"] == "No HTTPS" for rule in result["rules"]))

    def test_userinfo_adds_rule(self):
        result = analyze_url("https://trusted.example@evil.example/")
        self.assertTrue(any(rule["name"] == "User-info in authority" for rule in result["rules"]))

    def test_ip_host_adds_rule(self):
        result = analyze_url("https://192.0.2.10/login")
        self.assertTrue(any(rule["name"] == "IP address hostname" for rule in result["rules"]))

    def test_rejects_whitespace_and_controls(self):
        self.assertFalse(analyze_url("https://example.com/a b")["valid"])
        self.assertFalse(analyze_url("https://example.com/\n")["valid"])

    def test_rejects_oversized_input(self):
        self.assertFalse(analyze_url("https://example.com/" + "a" * MAX_URL_LENGTH)["valid"])

    def test_score_is_bounded(self):
        result = analyze_url("http://paypal-login-account-verify.example:8080/a" + "x" * 180)
        self.assertTrue(result["valid"])
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_no_network_client_imports(self):
        # Architectural reminder: analyzer.py is deliberately standard-library-only.
        import analyzer
        self.assertFalse(hasattr(analyzer, "requests"))


if __name__ == "__main__":
    unittest.main()
