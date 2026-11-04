from io import StringIO
from django.contrib.auth import get_user_model
from django.core.management import call_command, CommandError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from incidents.models import Incident

class IncidentSecurityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.alice = get_user_model().objects.create_user(username="alice", password="test-password-only")
        cls.bob = get_user_model().objects.create_user(username="bob", password="test-password-only")
        cls.alice_incident = Incident.objects.create(title="Alice private report", description="Alice synthetic incident details.", created_by=cls.alice)
        cls.bob_incident = Incident.objects.create(title="Bob private report", description="Bob synthetic incident details.", created_by=cls.bob)

    def test_anonymous_views_require_login(self):
        for url in [reverse("incidents:list"), reverse("incidents:create"), reverse("incidents:detail", args=[self.alice_incident.pk])]:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertRedirects(response, f"{reverse('login')}?next={url}", fetch_redirect_response=False)

    def test_anonymous_cannot_create_incident(self):
        before = Incident.objects.count()
        response = self.client.post(reverse("incidents:create"), {"title": "Anonymous attempt", "description": "This should not be created."})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Incident.objects.count(), before)

    def test_list_contains_only_owned_incidents(self):
        self.client.force_login(self.alice)
        response = self.client.get(reverse("incidents:list"))
        self.assertContains(response, "Alice private report")
        self.assertNotContains(response, "Bob private report")
        self.assertEqual(response.context["paginator"].count, 1)

    def test_owner_can_open_incident(self):
        self.client.force_login(self.alice)
        self.assertContains(self.client.get(reverse("incidents:detail", args=[self.alice_incident.pk])), "Alice synthetic incident details.")

    def test_other_users_incident_and_missing_incident_are_not_found(self):
        self.client.force_login(self.alice)
        for pk in [self.bob_incident.pk, 999999]:
            self.assertEqual(self.client.get(reverse("incidents:detail", args=[pk])).status_code, 404)

    def test_owner_is_bound_server_side_even_if_client_supplies_another(self):
        self.client.force_login(self.alice)
        response = self.client.post(reverse("incidents:create"), {
            "title": "A newly reported issue", "description": "A synthetic issue with enough detail.",
            "created_by": self.bob.pk,
        })
        obj = Incident.objects.get(title="A newly reported issue")
        self.assertEqual(obj.created_by, self.alice)
        self.assertRedirects(response, reverse("incidents:detail", args=[obj.pk]))

    def test_invalid_and_overlong_input_is_rejected_without_writing(self):
        self.client.force_login(self.alice)
        for title, description in [("a", "short"), ("x" * 151, "Valid description text"), ("Valid title", "x" * 5001)]:
            before = Incident.objects.count()
            response = self.client.post(reverse("incidents:create"), {"title": title, "description": description})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.context["form"].errors)
            self.assertEqual(Incident.objects.count(), before)

    def test_script_shaped_text_is_escaped_on_list_and_detail(self):
        self.client.force_login(self.alice)
        payload = "<script>alert('lab')</script>"
        item = Incident.objects.create(title=payload, description=payload, created_by=self.alice)
        for url in [reverse("incidents:list"), reverse("incidents:detail", args=[item.pk])]:
            response = self.client.get(url)
            self.assertNotContains(response, payload)
            self.assertContains(response, "&lt;script&gt;")

    def test_sql_shaped_title_is_stored_as_data(self):
        self.client.force_login(self.alice)
        title = "' OR '1'='1"
        response = self.client.post(reverse("incidents:create"), {"title": title, "description": "A SQL-shaped title used as harmless data."})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Incident.objects.get(title=title).created_by, self.alice)
        self.assertEqual(get_user_model().objects.count(), 2)

    def test_create_requires_csrf_proof(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.alice)
        data = {"title": "CSRF test report", "description": "A synthetic CSRF verification record."}
        self.assertEqual(client.post(reverse("incidents:create"), data).status_code, 403)
        client.get(reverse("incidents:create"))
        token = client.cookies["incidentdesk_csrf"].value
        response = client.post(reverse("incidents:create"), {**data, "csrfmiddlewaretoken": token})
        self.assertEqual(response.status_code, 302)

    def test_cross_origin_post_is_rejected_even_with_cookie_and_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.alice)
        client.get(reverse("incidents:create"))
        response = client.post(reverse("incidents:create"), {
            "title": "Origin test", "description": "A synthetic origin mismatch test.",
            "csrfmiddlewaretoken": client.cookies["incidentdesk_csrf"].value,
        }, HTTP_ORIGIN="https://attacker.invalid")
        self.assertEqual(response.status_code, 403)

    def test_private_pages_have_no_store_and_security_headers(self):
        self.client.force_login(self.alice)
        response = self.client.get(reverse("incidents:list"))
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])

    def test_normal_user_cannot_enter_admin(self):
        self.client.force_login(self.alice)
        response = self.client.get("/admin/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/login/", response.headers["Location"])

    @override_settings(DEBUG=True)
    def test_seed_is_idempotent_and_creates_no_accounts(self):
        for _ in range(2):
            call_command("seed_incidents", username="alice", stdout=StringIO())
        self.assertEqual(self.alice.incidents.count(), 3)
        self.assertEqual(get_user_model().objects.count(), 2)

    @override_settings(DEBUG=False)
    def test_seed_refuses_production(self):
        with self.assertRaises(CommandError):
            call_command("seed_incidents", username="alice", stdout=StringIO())

class SessionTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="reporter", password="test-password-only")

    def test_valid_login_and_safe_next_redirect(self):
        response = self.client.post(reverse("login"), {"username": "reporter", "password": "test-password-only", "next": "https://attacker.invalid/"})
        self.assertRedirects(response, reverse("incidents:list"))

    def test_invalid_login_is_generic(self):
        response = self.client.post(reverse("login"), {"username": "reporter", "password": "wrong"})
        self.assertContains(response, "Check your username and password.")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_login_rotates_existing_session_key(self):
        session = self.client.session
        session["anonymous_note"] = "synthetic"
        session.save()
        old = session.session_key
        self.assertTrue(self.client.login(username="reporter", password="test-password-only"))
        self.assertNotEqual(self.client.session.session_key, old)
        from django.contrib.sessions.models import Session
        self.assertFalse(Session.objects.filter(session_key=old).exists())

    def test_logout_requires_post_and_csrf_then_invalidates_session(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.get(reverse("logout")).status_code, 405)
        self.assertEqual(client.post(reverse("logout")).status_code, 403)
        client.get(reverse("incidents:list"))
        old = client.session.session_key
        response = client.post(reverse("logout"), {"csrfmiddlewaretoken": client.cookies["incidentdesk_csrf"].value})
        self.assertEqual(response.status_code, 302)
        from django.contrib.sessions.models import Session
        self.assertFalse(Session.objects.filter(session_key=old).exists())
        self.assertNotIn("_auth_user_id", client.session)
