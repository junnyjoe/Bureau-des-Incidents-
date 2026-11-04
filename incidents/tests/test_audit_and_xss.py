from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import Client, TestCase
from django.urls import reverse

from incidents.audit import record_audit_event
from incidents.models import AuditEvent, Comment, Incident
from incidents.permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS

class AuditAndXssSecurityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.analysts_group = Group.objects.create(name=ROLE_ANALYSTS)
        cls.admins_group = Group.objects.create(name=ROLE_ADMINISTRATORS)

        cls.alice = User.objects.create_user(username="alice_xss", password="test-password-only")
        cls.bob = User.objects.create_user(username="bob_xss", password="test-password-only")

        cls.charlie = User.objects.create_user(username="charlie_xss", password="test-password-only")
        cls.charlie.groups.add(cls.analysts_group)

        cls.eve = User.objects.create_user(username="eve_xss", password="test-password-only")
        cls.eve.groups.add(cls.admins_group)

        cls.alice_incident = Incident.objects.create(
            title="Alice production alert",
            description="Alice reported a suspicious access anomaly.",
            created_by=cls.alice,
        )
        cls.bob_incident = Incident.objects.create(
            title="Bob internal report",
            description="Bob reported an unassigned internal event.",
            created_by=cls.bob,
        )

    # --- Stored XSS Neutralization Tests ---

    def test_comment_stored_xss_payload_stays_inert(self):
        """Stored XSS: Dangerous markup must remain inert and auto-escaped plain-text."""
        self.client.force_login(self.alice)
        xss_payload = "<script>alert('XSS_ATTACK')</script><img src=x onerror=alert(1)>"
        
        response = self.client.post(
            reverse("incidents:add_comment", args=[self.alice_incident.pk]),
            {"body": xss_payload},
        )
        self.assertRedirects(response, reverse("incidents:detail", args=[self.alice_incident.pk]))

        # Inspect the rendered HTML on the detail view
        detail_resp = self.client.get(reverse("incidents:detail", args=[self.alice_incident.pk]))
        self.assertEqual(detail_resp.status_code, 200)

        # Unescaped script tags must NOT be present
        self.assertNotContains(detail_resp, "<script>alert('XSS_ATTACK')</script>")
        self.assertNotContains(detail_resp, "<img src=x onerror=alert(1)>")

        # Escaped characters must be present as inert plain text
        self.assertContains(detail_resp, "&lt;script&gt;alert")

    def test_comment_requires_csrf_protection(self):
        """CSRF protection: comment submission without valid CSRF is denied with 403."""
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.alice)
        
        # Missing CSRF token
        response = csrf_client.post(
            reverse("incidents:add_comment", args=[self.alice_incident.pk]),
            {"body": "Valid comment without CSRF token."},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Comment.objects.count(), 0)

    def test_comment_author_and_incident_bound_server_side(self):
        """Mass-assignment: author and incident cannot be forged from client parameters."""
        self.client.force_login(self.alice)
        response = self.client.post(
            reverse("incidents:add_comment", args=[self.alice_incident.pk]),
            {
                "body": "Legitimate operational note.",
                "author": self.bob.pk,  # attempt to forge author
                "incident": self.bob_incident.pk,  # attempt to attach to Bob's incident
            },
        )
        self.assertRedirects(response, reverse("incidents:detail", args=[self.alice_incident.pk]))
        
        comment = Comment.objects.get(body="Legitimate operational note.")
        self.assertEqual(comment.author, self.alice)
        self.assertEqual(comment.incident, self.alice_incident)

    def test_comment_denied_on_unauthorized_incident(self):
        """Scoping: Alice cannot comment on Bob's incident."""
        self.client.force_login(self.alice)
        response = self.client.post(
            reverse("incidents:add_comment", args=[self.bob_incident.pk]),
            {"body": "Unauthorized cross-tenant comment attempt."},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(Comment.objects.filter(incident=self.bob_incident).count(), 0)

    # --- Security Audit Logging Tests ---

    def test_audit_event_recorded_on_comment(self):
        self.client.force_login(self.alice)
        self.client.post(
            reverse("incidents:add_comment", args=[self.alice_incident.pk]),
            {"body": "Audited comment message."},
        )
        event = AuditEvent.objects.filter(
            action=AuditEvent.Action.COMMENT_ADDED,
            incident=self.alice_incident,
        ).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.username_snapshot, "alice_xss")

    def test_audit_event_recorded_on_assignment_and_status(self):
        # 1. Admin assigns analyst
        self.client.force_login(self.eve)
        self.client.post(
            reverse("incidents:assign", args=[self.alice_incident.pk]),
            {"assigned_to": self.charlie.pk},
        )
        assign_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.ASSIGNMENT,
            incident=self.alice_incident,
        ).first()
        self.assertIsNotNone(assign_event)
        self.assertEqual(assign_event.username_snapshot, "eve_xss")

        # 2. Analyst transitions status
        self.client.force_login(self.charlie)
        self.client.post(
            reverse("incidents:update_status", args=[self.alice_incident.pk]),
            {"status": Incident.Status.IN_PROGRESS},
        )
        status_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.STATUS_CHANGE,
            incident=self.alice_incident,
        ).first()
        self.assertIsNotNone(status_event)
        self.assertEqual(status_event.username_snapshot, "charlie_xss")

    def test_no_secrets_in_audit_records(self):
        """Audit safety: logs must never contain secrets or credentials."""
        record_audit_event(
            action=AuditEvent.Action.LOGIN_FAILED,
            details="Failed login attempt for username 'eve_xss'",
        )
        event = AuditEvent.objects.filter(action=AuditEvent.Action.LOGIN_FAILED).latest("created_at")
        self.assertNotIn("test-password-only", event.details)
        self.assertNotIn("SECRET_KEY", event.details)
        self.assertNotIn("token", event.details.lower())
