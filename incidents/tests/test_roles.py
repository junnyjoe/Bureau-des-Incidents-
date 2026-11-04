from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from incidents.models import Incident
from incidents.permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS

class RolePolicyAndAccessMatrixTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.analysts_group = Group.objects.create(name=ROLE_ANALYSTS)
        cls.admins_group = Group.objects.create(name=ROLE_ADMINISTRATORS)

        # 1. Reporters (ordinary users)
        cls.alice = User.objects.create_user(username="reporter_alice", password="test-password-only")
        cls.bob = User.objects.create_user(username="reporter_bob", password="test-password-only")

        # 2. Analysts
        cls.charlie = User.objects.create_user(username="analyst_charlie", password="test-password-only")
        cls.charlie.groups.add(cls.analysts_group)

        cls.david = User.objects.create_user(username="analyst_david", password="test-password-only")
        cls.david.groups.add(cls.analysts_group)

        # 3. Application Administrator (ordinary user with admin group, not superuser)
        cls.eve = User.objects.create_user(username="admin_eve", password="test-password-only")
        cls.eve.groups.add(cls.admins_group)

        # Incidents
        cls.inc_alice_unassigned = Incident.objects.create(
            title="Alice unassigned issue",
            description="Alice reported this synthetic issue.",
            created_by=cls.alice,
        )
        cls.inc_alice_assigned_charlie = Incident.objects.create(
            title="Alice issue assigned to Charlie",
            description="Alice reported this, Charlie is assigned.",
            created_by=cls.alice,
            assigned_to=cls.charlie,
        )
        cls.inc_bob_unassigned = Incident.objects.create(
            title="Bob unassigned issue",
            description="Bob reported this synthetic issue.",
            created_by=cls.bob,
        )
        cls.inc_bob_assigned_david = Incident.objects.create(
            title="Bob issue assigned to David",
            description="Bob reported this, David is assigned.",
            created_by=cls.bob,
            assigned_to=cls.david,
        )

    # --- Reporter Access Matrix & Denial Tests ---

    def test_reporter_can_view_own_incidents_only(self):
        self.client.force_login(self.alice)
        # Can view own unassigned
        resp = self.client.get(reverse("incidents:detail", args=[self.inc_alice_unassigned.pk]))
        self.assertEqual(resp.status_code, 200)

        # Can view own assigned
        resp = self.client.get(reverse("incidents:detail", args=[self.inc_alice_assigned_charlie.pk]))
        self.assertEqual(resp.status_code, 200)

        # List contains only Alice's 2 incidents
        list_resp = self.client.get(reverse("incidents:list"))
        self.assertEqual(list_resp.context["paginator"].count, 2)
        self.assertContains(list_resp, "Alice unassigned issue")
        self.assertNotContains(list_resp, "Bob unassigned issue")

    def test_reporter_denied_access_to_other_owners_incident(self):
        self.client.force_login(self.alice)
        # Attempt to access Bob's incident -> 404 (does not exist in Alice's scope)
        resp = self.client.get(reverse("incidents:detail", args=[self.inc_bob_unassigned.pk]))
        self.assertEqual(resp.status_code, 404)

        resp = self.client.get(reverse("incidents:detail", args=[self.inc_bob_assigned_david.pk]))
        self.assertEqual(resp.status_code, 404)

    # --- Analyst Access Matrix & Denial Tests ---

    def test_analyst_can_view_assigned_incident(self):
        self.client.force_login(self.charlie)
        resp = self.client.get(reverse("incidents:detail", args=[self.inc_alice_assigned_charlie.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Alice issue assigned to Charlie")

    def test_analyst_denied_access_to_unassigned_incident(self):
        """Unassigned denial test: an analyst cannot access an unassigned incident they did not create."""
        self.client.force_login(self.charlie)
        resp = self.client.get(reverse("incidents:detail", args=[self.inc_alice_unassigned.pk]))
        self.assertEqual(resp.status_code, 404)

    def test_analyst_denied_access_to_other_analysts_incident(self):
        """Other-owner denial test: an analyst cannot access another analyst's assigned incident."""
        self.client.force_login(self.charlie)
        resp = self.client.get(reverse("incidents:detail", args=[self.inc_bob_assigned_david.pk]))
        self.assertEqual(resp.status_code, 404)

    # --- Administrator Access Matrix ---

    def test_administrator_can_view_all_incidents(self):
        self.client.force_login(self.eve)
        for inc in [
            self.inc_alice_unassigned,
            self.inc_alice_assigned_charlie,
            self.inc_bob_unassigned,
            self.inc_bob_assigned_david,
        ]:
            with self.subTest(pk=inc.pk):
                resp = self.client.get(reverse("incidents:detail", args=[inc.pk]))
                self.assertEqual(resp.status_code, 200)

        list_resp = self.client.get(reverse("incidents:list"))
        self.assertEqual(list_resp.context["paginator"].count, 4)

    # --- Function Denial Tests (Assign Analyst) ---

    def test_reporter_cannot_assign_analyst(self):
        """Function denial: ordinary reporter cannot perform analyst assignment."""
        self.client.force_login(self.alice)
        resp = self.client.post(
            reverse("incidents:assign", args=[self.inc_alice_unassigned.pk]),
            {"assigned_to": self.charlie.pk},
        )
        self.assertEqual(resp.status_code, 403)
        self.inc_alice_unassigned.refresh_from_db()
        self.assertIsNone(self.inc_alice_unassigned.assigned_to)

    def test_analyst_cannot_assign_analyst(self):
        """Function denial: analysts cannot perform assignment/reassignment."""
        self.client.force_login(self.charlie)
        resp = self.client.post(
            reverse("incidents:assign", args=[self.inc_alice_assigned_charlie.pk]),
            {"assigned_to": self.david.pk},
        )
        self.assertEqual(resp.status_code, 403)
        self.inc_alice_assigned_charlie.refresh_from_db()
        self.assertEqual(self.inc_alice_assigned_charlie.assigned_to, self.charlie)

    def test_admin_can_assign_analyst(self):
        self.client.force_login(self.eve)
        resp = self.client.post(
            reverse("incidents:assign", args=[self.inc_bob_unassigned.pk]),
            {"assigned_to": self.charlie.pk},
        )
        self.assertRedirects(resp, reverse("incidents:detail", args=[self.inc_bob_unassigned.pk]))
        self.inc_bob_unassigned.refresh_from_db()
        self.assertEqual(self.inc_bob_unassigned.assigned_to, self.charlie)

    # --- Function Denial Tests (Status Update) ---

    def test_reporter_cannot_update_status(self):
        """Function denial: reporters cannot update incident status."""
        self.client.force_login(self.alice)
        resp = self.client.post(
            reverse("incidents:update_status", args=[self.inc_alice_unassigned.pk]),
            {"status": Incident.Status.IN_PROGRESS},
        )
        self.assertEqual(resp.status_code, 403)
        self.inc_alice_unassigned.refresh_from_db()
        self.assertEqual(self.inc_alice_unassigned.status, Incident.Status.OPEN)

    def test_assigned_analyst_can_update_status(self):
        self.client.force_login(self.charlie)
        resp = self.client.post(
            reverse("incidents:update_status", args=[self.inc_alice_assigned_charlie.pk]),
            {"status": Incident.Status.IN_PROGRESS},
        )
        self.assertRedirects(resp, reverse("incidents:detail", args=[self.inc_alice_assigned_charlie.pk]))
        self.inc_alice_assigned_charlie.refresh_from_db()
        self.assertEqual(self.inc_alice_assigned_charlie.status, Incident.Status.IN_PROGRESS)

    def test_unassigned_analyst_cannot_update_status_of_other_incident(self):
        """Function denial: analyst cannot update status of an incident assigned to another analyst."""
        self.client.force_login(self.charlie)
        resp = self.client.post(
            reverse("incidents:update_status", args=[self.inc_bob_assigned_david.pk]),
            {"status": Incident.Status.IN_PROGRESS},
        )
        # Scoping returns 404 because the incident is outside Charlie's view
        self.assertEqual(resp.status_code, 404)
        self.inc_bob_assigned_david.refresh_from_db()
        self.assertEqual(self.inc_bob_assigned_david.status, Incident.Status.OPEN)
