from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from incidents.models import AuditEvent
from incidents.ratelimit import reset_rate_limit


class LoginRateLimitSecurityTests(TestCase):
    """
    Automated security tests for login brute-force and credential-stuffing defense.
    Verifies:
    - Attempt counting and threshold enforcement (HTTP 429).
    - Immutable audit event logging (LOGIN_SUCCESS and LOGIN_FAILED).
    - Counter clearing on successful authentication.
    - IP isolation (one locked IP does not affect another).
    """

    def setUp(self):
        cache.clear()
        self.username = "target_reporter"
        self.password = "ValidSecretPassword123!"
        self.user = get_user_model().objects.create_user(
            username=self.username,
            password=self.password,
        )
        self.login_url = reverse("login")
        self.client_ip = "192.0.2.1"
        reset_rate_limit(self.client_ip)

    def tearDown(self):
        cache.clear()

    def _post_login(self, username, password, ip=None):
        remote_addr = ip or self.client_ip
        return self.client.post(
            self.login_url,
            {"username": username, "password": password},
            REMOTE_ADDR=remote_addr,
        )

    def test_successful_login_records_audit_event_and_clears_counter(self):
        # Initial failed attempt
        self._post_login(self.username, "wrong_password")
        self.assertEqual(
            AuditEvent.objects.filter(action=AuditEvent.Action.LOGIN_FAILED).count(), 1
        )

        # Successful login
        response = self._post_login(self.username, self.password)
        self.assertRedirects(response, reverse("incidents:list"))

        # Verifies LOGIN_SUCCESS audit event
        success_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.LOGIN_SUCCESS
        ).first()
        self.assertIsNotNone(success_event)
        self.assertEqual(success_event.username_snapshot, self.username)
        self.assertEqual(success_event.ip_address, self.client_ip)

    def test_failed_login_records_generic_error_and_audit_event(self):
        response = self._post_login(self.username, "wrong_password")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Check your username and password.")

        failed_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.LOGIN_FAILED
        ).latest("created_at")
        self.assertIn("Failed login attempt (1/5)", failed_event.details)
        self.assertEqual(failed_event.ip_address, self.client_ip)

    def test_repeated_failed_logins_trigger_429_lockout(self):
        # 4 failed attempts: status code stays 200 with standard form error
        for i in range(1, 5):
            response = self._post_login(self.username, f"bad_password_{i}")
            self.assertEqual(response.status_code, 200)

        # 5th failed attempt: triggers lockout with HTTP 429
        response_lockout = self._post_login(self.username, "bad_password_5")
        self.assertEqual(response_lockout.status_code, 429)
        self.assertContains(
            response_lockout,
            "Too many failed login attempts",
            status_code=429,
        )

        # Verifies lockout audit record
        lockout_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.LOGIN_FAILED
        ).latest("created_at")
        self.assertIn("Rate limit exceeded", lockout_event.details)

    def test_subsequent_post_while_locked_out_returns_429_immediately(self):
        # Lockout the IP with 5 failed attempts
        for i in range(5):
            self._post_login(self.username, f"bad_password_{i}")

        # 6th attempt (even with valid password!) is immediately rejected with 429
        response = self._post_login(self.username, self.password)
        self.assertEqual(response.status_code, 429)
        self.assertContains(
            response,
            "temporarily locked for security",
            status_code=429,
        )

    def test_different_ip_is_not_affected_by_lockout(self):
        # Lockout IP 192.0.2.1
        for i in range(5):
            self._post_login(self.username, f"bad_{i}", ip="192.0.2.1")

        # IP 198.51.100.2 can still authenticate successfully
        alt_response = self._post_login(self.username, self.password, ip="198.51.100.2")
        self.assertRedirects(alt_response, reverse("incidents:list"))

    def test_successful_login_resets_attempt_counter(self):
        # 3 failed attempts
        for i in range(3):
            self._post_login(self.username, f"bad_{i}")

        # Legitimate login resets the counter
        success_response = self._post_login(self.username, self.password)
        self.assertRedirects(success_response, reverse("incidents:list"))

        # Logout
        self.client.logout()

        # Subsequent failure starts back at attempt 1/5
        resp_after = self._post_login(self.username, "another_bad_password")
        self.assertEqual(resp_after.status_code, 200)

        latest_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.LOGIN_FAILED
        ).latest("created_at")
        self.assertIn("(1/5)", latest_event.details)
