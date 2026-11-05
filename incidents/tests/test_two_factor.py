import time
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from incidents.models import AuditEvent, UserTOTPDevice
from incidents.permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS
from incidents.ratelimit import reset_rate_limit
from incidents.totp import (
    generate_totp_secret,
    get_totp_code,
    get_totp_uri,
    verify_totp_code,
)


class TwoFactorAuthenticationTests(TestCase):
    """
    Automated security tests for Two-Factor Authentication (RFC 6238 TOTP).
    Verifies:
    - Pure RFC 6238 algorithm (generation, window drift, URI formatting).
    - Privileged role enforcement (Analysts & Admins required, Reporters bypass).
    - Secret provisioning & device enrollment.
    - Security audit logging and denial on bad tokens.
    """

    def setUp(self):
        cache.clear()
        self.User = get_user_model()
        self.analysts_group = Group.objects.create(name=ROLE_ANALYSTS)
        self.admins_group = Group.objects.create(name=ROLE_ADMINISTRATORS)

        self.reporter = self.User.objects.create_user(
            username="test_reporter_2fa",
            password="ValidPassword123!",
        )
        self.analyst = self.User.objects.create_user(
            username="test_analyst_2fa",
            password="ValidPassword123!",
        )
        self.analyst.groups.add(self.analysts_group)

        self.admin_user = self.User.objects.create_user(
            username="test_admin_2fa",
            password="ValidPassword123!",
        )
        self.admin_user.groups.add(self.admins_group)

        self.login_url = reverse("login")
        self.verify_url = reverse("two_factor_verify")
        self.client_ip = "192.0.2.55"
        reset_rate_limit(self.client_ip)

    def tearDown(self):
        cache.clear()

    # --- Unit Algorithm Tests ---

    def test_totp_generation_and_verification(self):
        secret = generate_totp_secret()
        self.assertEqual(len(secret), 32)
        code = get_totp_code(secret)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())
        self.assertTrue(verify_totp_code(secret, code))

    def test_totp_drift_window_acceptance(self):
        secret = generate_totp_secret()
        # Code from 25 seconds ago should be valid (within window=1 step)
        past_code = get_totp_code(secret, for_time=time.time() - 25)
        self.assertTrue(verify_totp_code(secret, past_code, window=1))

        # Code from 3 minutes ago should be invalid
        ancient_code = get_totp_code(secret, for_time=time.time() - 180)
        self.assertFalse(verify_totp_code(secret, ancient_code, window=1))

    def test_totp_invalid_code_rejected(self):
        secret = generate_totp_secret()
        self.assertFalse(verify_totp_code(secret, "000000"))
        self.assertFalse(verify_totp_code(secret, "invalid"))
        self.assertFalse(verify_totp_code(secret, ""))

    def test_totp_uri_formatting(self):
        secret = "JBSWY3DPEHPK3PXP"
        uri = get_totp_uri(secret, "analyst1")
        self.assertIn("otpauth://totp/", uri)
        self.assertIn("secret=JBSWY3DPEHPK3PXP", uri)
        self.assertIn("IncidentDesk", uri)

    # --- Workflow Integration Tests ---

    def test_standard_reporter_bypasses_2fa(self):
        # Reporter logs in directly
        response = self.client.post(
            self.login_url,
            {"username": "test_reporter_2fa", "password": "ValidPassword123!"},
            REMOTE_ADDR=self.client_ip,
        )
        self.assertRedirects(response, reverse("incidents:list"))
        self.assertIn("_auth_user_id", self.client.session)

    def test_analyst_is_redirected_to_2fa_verification(self):
        # Analyst submits valid password
        response = self.client.post(
            self.login_url,
            {"username": "test_analyst_2fa", "password": "ValidPassword123!"},
            REMOTE_ADDR=self.client_ip,
        )
        # Not logged in yet! Redirected to 2FA verification view
        self.assertRedirects(response, self.verify_url)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(self.client.session["pre_2fa_user_id"], self.analyst.pk)

    def test_2fa_verify_page_displays_enrollment_details_for_new_device(self):
        # Initiate 2FA session
        self.client.post(
            self.login_url,
            {"username": "test_analyst_2fa", "password": "ValidPassword123!"},
            REMOTE_ADDR=self.client_ip,
        )

        response = self.client.get(self.verify_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Initial Enrollment Required")
        self.assertContains(response, "test_analyst_2fa")

    def test_valid_2fa_code_completes_authentication_and_records_audit(self):
        # 1. Step 1: Login with password
        self.client.post(
            self.login_url,
            {"username": "test_analyst_2fa", "password": "ValidPassword123!"},
            REMOTE_ADDR=self.client_ip,
        )

        # 2. Retrieve provisioned device secret and generate valid token
        device = UserTOTPDevice.objects.get(user=self.analyst)
        valid_code = get_totp_code(device.secret)

        # 3. Step 2: Submit valid TOTP code
        response = self.client.post(
            self.verify_url,
            {"code": valid_code},
            REMOTE_ADDR=self.client_ip,
        )

        # Successfully logged in!
        self.assertRedirects(response, reverse("incidents:list"))
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.analyst.pk)

        device.refresh_from_db()
        self.assertTrue(device.is_confirmed)
        self.assertIsNotNone(device.last_verified_at)

        # Audit log verification
        audit_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.TWO_FACTOR_VERIFIED,
            user=self.analyst,
        ).first()
        self.assertIsNotNone(audit_event)
        self.assertIn("TOTP", audit_event.details)

    def test_invalid_2fa_code_is_rejected_and_audited(self):
        # 1. Step 1: Login
        self.client.post(
            self.login_url,
            {"username": "test_analyst_2fa", "password": "ValidPassword123!"},
            REMOTE_ADDR=self.client_ip,
        )

        # 2. Step 2: Submit bad code
        response = self.client.post(
            self.verify_url,
            {"code": "999999"},
            REMOTE_ADDR=self.client_ip,
        )
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid verification code", status_code=400)
        self.assertNotIn("_auth_user_id", self.client.session)

        # Audit failure event
        fail_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.TWO_FACTOR_FAILED,
            user=self.analyst,
        ).first()
        self.assertIsNotNone(fail_event)

    def test_direct_access_without_pending_session_redirects_to_login(self):
        response = self.client.get(self.verify_url)
        self.assertRedirects(response, self.login_url)
