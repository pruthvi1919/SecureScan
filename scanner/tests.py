from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient

from .models import Scan
from .services.engine import (
    ScanResult,
    calculate_score,
    check_cookies,
    check_information_disclosure,
    check_security_headers,
    make_finding,
)
from .services.ssrf import UnsafeTargetError, validate_target


class SSRFProtectionTests(SimpleTestCase):
    def test_blocks_internal_addresses(self):
        for url in [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata service
            "http://[::1]/",
            "http://0.0.0.0/",
            "http://2130706433/",  # 127.0.0.1 written as a number
        ]:
            with self.subTest(url=url), self.assertRaises(UnsafeTargetError):
                validate_target(url)

    def test_blocks_bad_schemes_ports_and_credentials(self):
        for url in [
            "ftp://8.8.8.8/",
            "file:///etc/passwd",
            "http://8.8.8.8:22/",
            "http://user:pass@8.8.8.8/",
        ]:
            with self.subTest(url=url), self.assertRaises(UnsafeTargetError):
                validate_target(url)

    def test_allows_public_address(self):
        self.assertEqual(validate_target("https://8.8.8.8/"), "8.8.8.8")


class CheckTests(SimpleTestCase):
    def test_missing_headers_all_fail(self):
        findings = check_security_headers({}, is_https=True)
        self.assertEqual(len(findings), 6)
        self.assertFalse(any(f["passed"] for f in findings))

    def test_good_headers_all_pass(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }
        # X-Frame-Options is not set, but CSP frame-ancestors covers it.
        self.assertTrue(all(f["passed"] for f in check_security_headers(headers, True)))

    def test_hsts_fails_on_plain_http(self):
        findings = check_security_headers({"Strict-Transport-Security": "max-age=1"}, False)
        hsts = next(f for f in findings if f["check_name"] == "Strict-Transport-Security")
        self.assertFalse(hsts["passed"])

    def test_version_disclosure(self):
        findings = check_information_disclosure(
            {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}
        )
        self.assertEqual(sum(not f["passed"] for f in findings), 2)

    def test_cookie_flags(self):
        findings = check_cookies([
            "sessionid=abc; Path=/",
            "csrftoken=x; Secure; HttpOnly; SameSite=Lax",
        ])
        self.assertFalse(findings[0]["passed"])
        self.assertIn("Secure, HttpOnly, SameSite", findings[0]["description"])
        self.assertTrue(findings[1]["passed"])

    def test_scoring(self):
        self.assertEqual(calculate_score([]), (100, "A"))
        high_fail = make_finding("headers", "x", "high", False, "d")
        low_fail = make_finding("headers", "y", "low", False, "d")
        self.assertEqual(calculate_score([high_fail]), (80, "B"))
        self.assertEqual(calculate_score([high_fail, low_fail]), (75, "C"))
        self.assertEqual(calculate_score([high_fail] * 6), (0, "F"))


FAKE_RESULT = ScanResult(
    final_url="https://8.8.8.8/",
    findings=[
        make_finding("headers", "Content-Security-Policy", "medium", False, "missing",
                     "add it", ("OWASP A03:2021 Injection",)),
        make_finding("transport", "HTTPS", "high", True, "ok"),
    ],
    score=90,
    grade="A",
)


class ScanAPITests(TestCase):
    password = "S3cure-Pass-2026!"

    def setUp(self):
        cache.clear()  # reset rate-limit counters between tests
        self.client = APIClient()
        self.alice = User.objects.create_user("alice", password=self.password)
        self.bob = User.objects.create_user("bob", password=self.password)

    def login(self, username):
        response = self.client.post(
            "/api/auth/token/", {"username": username, "password": self.password}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access']}")

    def test_register_does_not_return_password(self):
        response = self.client.post(
            "/api/auth/register/",
            {"username": "carol", "password": "Another-Strong-Pass-1"},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("password", response.data)

    def test_register_rejects_weak_password(self):
        response = self.client.post(
            "/api/auth/register/", {"username": "dave", "password": "12345678"}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_scans_require_login(self):
        self.assertEqual(self.client.get("/api/scans/").status_code, 401)

    @mock.patch("scanner.views.run_scan", return_value=FAKE_RESULT)
    def test_create_scan_and_report(self, _mock_scan):
        self.login("alice")
        response = self.client.post("/api/scans/", {"target_url": "8.8.8.8"}, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["target_url"], "https://8.8.8.8")  # https:// added
        self.assertEqual(response.data["grade"], "A")
        self.assertEqual(len(response.data["findings"]), 2)
        self.assertEqual(response.data["failed_checks"], 1)

        report = self.client.get(f"/api/scans/{response.data['id']}/report/")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.data["summary"]["failed"], 1)
        self.assertEqual(report.data["compliance_gaps"][0]["control"], "OWASP A03:2021 Injection")

    def test_ssrf_target_rejected_by_api(self):
        self.login("alice")
        response = self.client.post(
            "/api/scans/", {"target_url": "http://127.0.0.1:8000/admin/"}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Scan.objects.count(), 0)

    def test_users_cannot_see_each_others_scans(self):
        scan = Scan.objects.create(user=self.alice, target_url="https://8.8.8.8")
        self.login("bob")
        self.assertEqual(self.client.get(f"/api/scans/{scan.id}/").status_code, 404)
        self.assertEqual(self.client.get("/api/scans/").data["count"], 0)
