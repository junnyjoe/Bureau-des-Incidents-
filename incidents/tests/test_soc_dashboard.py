from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from incidents.models import Incident
from incidents.permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS


class SOCDashboardTests(TestCase):
    """
    Automated tests for SOC Triage Dashboard.
    Verifies metric aggregation, authorization scoping, and UI display.
    """

    def setUp(self):
        User = get_user_model()
        self.analysts_group = Group.objects.create(name=ROLE_ANALYSTS)
        self.admins_group = Group.objects.create(name=ROLE_ADMINISTRATORS)

        self.reporter = User.objects.create_user(username="dash_reporter", password="ValidPassword123!")
        self.analyst = User.objects.create_user(username="dash_analyst", password="ValidPassword123!")
        self.analyst.groups.add(self.analysts_group)

        self.admin = User.objects.create_user(username="dash_admin", password="ValidPassword123!")
        self.admin.groups.add(self.admins_group)

        Incident.objects.create(
            title="Critical DB failure",
            description="Production DB crash.",
            severity=Incident.Severity.CRITICAL,
            status=Incident.Status.OPEN,
            created_by=self.reporter,
        )
        Incident.objects.create(
            title="High severity network event",
            description="SYN flood on edge switch.",
            severity=Incident.Severity.HIGH,
            status=Incident.Status.IN_PROGRESS,
            created_by=self.reporter,
            assigned_to=self.analyst,
        )
        Incident.objects.create(
            title="Low severity disk alert",
            description="Disk 80 percent full.",
            severity=Incident.Severity.LOW,
            status=Incident.Status.RESOLVED,
            created_by=self.reporter,
        )

        self.dash_url = reverse("incidents:dashboard")

    def test_anonymous_redirected_to_login(self):
        response = self.client.get(self.dash_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_dashboard_computes_kpis_accurately(self):
        self.client.force_login(self.admin)

        response = self.client.get(self.dash_url)
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertEqual(context["total_incidents"], 3)
        self.assertEqual(context["critical_count"], 1)
        self.assertEqual(context["high_count"], 1)
        self.assertEqual(context["low_count"], 1)
        self.assertEqual(context["open_count"], 1)
        self.assertEqual(context["in_progress_count"], 1)
        self.assertEqual(context["resolved_count"], 1)
        self.assertEqual(context["unassigned_count"], 1)  # Only the OPEN one is unassigned

    def test_dashboard_renders_for_analyst(self):
        self.client.force_login(self.analyst)

        response = self.client.get(self.dash_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SOC Triage Dashboard")
        self.assertContains(response, "High severity network event")
