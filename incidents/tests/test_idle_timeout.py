import time
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from config.middleware import SessionIdleTimeoutMiddleware
from incidents.models import AuditEvent
from incidents.permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS


class SessionIdleTimeoutTests(TestCase):
    """
    Automated security tests for Session Idle Timeout.
    Ensures that inactive sessions are purged, users are logged out,
    and audit trails are reliably recorded.
    """

    def setUp(self):
        self.factory = RequestFactory()
        self.user = get_user_model().objects.create_user(
            username="timeout_user",
            password="TestPassword123!",
        )
        self.middleware = SessionIdleTimeoutMiddleware(lambda r: HttpResponse("OK"))

    def _create_request(self, user=None, last_activity=None):
        request = self.factory.get(reverse("incidents:list"))
        request.user = user or self.user
        session = SessionStore()
        if last_activity is not None:
            session["_last_activity"] = last_activity
        session.save()
        request.session = session
        setattr(request, "_messages", FallbackStorage(request))
        return request

    def test_anonymous_requests_are_unaffected(self):
        request = self._create_request(user=AnonymousUser())
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_active_session_updates_last_activity(self):
        now = time.time()
        request = self._create_request(last_activity=now - 30)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(request.session["_last_activity"], now)

    @override_settings(SESSION_IDLE_TIMEOUT=60)
    def test_idle_session_is_terminated_and_redirects_to_login(self):
        # Inactive for 120 seconds (greater than 60s timeout)
        inactive_time = time.time() - 120
        request = self._create_request(last_activity=inactive_time)

        response = self.middleware(request)

        # Expect redirect to login with expired notice parameter
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)
        self.assertIn("expired=1", response.url)

        # Audit log event must be persisted
        logout_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.LOGOUT,
            username_snapshot="timeout_user",
        ).first()
        self.assertIsNotNone(logout_event)
        self.assertIn("inactivity", logout_event.details)

    @override_settings(SESSION_IDLE_TIMEOUT=1800, SESSION_IDLE_TIMEOUT_PRIVILEGED=300)
    def test_privileged_roles_have_shorter_idle_timeout(self):
        # Add user to Administrators group
        admins_group, _ = Group.objects.get_or_create(name=ROLE_ADMINISTRATORS)
        self.user.groups.add(admins_group)

        # Inactive for 400 seconds: less than standard timeout (1800s), but exceeds privileged (300s)
        inactive_time = time.time() - 400
        request = self._create_request(last_activity=inactive_time)

        response = self.middleware(request)
        self.assertEqual(response.status_code, 302)
        self.assertIn("expired=1", response.url)
