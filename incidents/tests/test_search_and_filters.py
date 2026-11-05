from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from incidents.models import Incident


class SearchAndFilterSecurityTests(TestCase):
    """
    Automated security tests for Incident search and filtering.
    Verifies that search:
    - Works across keywords and reference IDs.
    - Strictly preserves owner and role scoping (no cross-tenant leakage).
    - Is fully immune to SQL injection through parameterized ORM lookups.
    """

    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user(username="alice_filter", password="ValidPassword123!")
        self.bob = User.objects.create_user(username="bob_filter", password="ValidPassword123!")

        self.inc_alice_laptop = Incident.objects.create(
            title="Alice laptop compromised",
            description="Alice synthetic malware alert on workstation.",
            severity=Incident.Severity.CRITICAL,
            status=Incident.Status.OPEN,
            created_by=self.alice,
        )
        self.inc_alice_wifi = Incident.objects.create(
            title="Alice wifi authentication failure",
            description="Alice reported intermittent 802.1X connection issues.",
            severity=Incident.Severity.LOW,
            status=Incident.Status.RESOLVED,
            created_by=self.alice,
        )
        self.inc_bob_private = Incident.objects.create(
            title="Bob confidential database breach",
            description="Bob private report containing sensitive internal details.",
            severity=Incident.Severity.CRITICAL,
            status=Incident.Status.OPEN,
            created_by=self.bob,
        )

        self.list_url = reverse("incidents:list")

    def test_search_by_keyword_matches_title_and_description(self):
        self.client.force_login(self.alice)

        response = self.client.get(self.list_url, {"q": "laptop"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alice laptop compromised")
        self.assertNotContains(response, "wifi")

    def test_search_by_reference_id(self):
        self.client.force_login(self.alice)

        ref = self.inc_alice_wifi.reference  # e.g. INC-0002
        response = self.client.get(self.list_url, {"q": ref})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alice wifi authentication failure")
        self.assertNotContains(response, "Alice laptop compromised")

    def test_search_preserves_strict_role_scoping(self):
        """Alice must NEVER see Bob's incident, even if searching for its exact keywords."""
        self.client.force_login(self.alice)

        # Searching for words present in Bob's incident
        response = self.client.get(self.list_url, {"q": "database breach"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Bob confidential database breach")
        self.assertNotContains(response, "Bob private report")

    def test_sql_injection_payloads_stay_inert_and_safe(self):
        """Boolean and union injection attempts must be treated as inert search literals."""
        self.client.force_login(self.alice)

        payloads = [
            "%' OR 1=1 -- ",
            "' UNION SELECT * FROM auth_user -- ",
            "'; DROP TABLE incidents_incident; --",
        ]
        for p in payloads:
            response = self.client.get(self.list_url, {"q": p})
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "Bob confidential database breach")

    def test_filter_by_severity(self):
        self.client.force_login(self.alice)

        response = self.client.get(self.list_url, {"severity": "critical"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alice laptop compromised")
        self.assertNotContains(response, "Alice wifi")

    def test_filter_by_status(self):
        self.client.force_login(self.alice)

        response = self.client.get(self.list_url, {"status": "resolved"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alice wifi authentication failure")
        self.assertNotContains(response, "Alice laptop")

    def test_combined_search_and_filter(self):
        self.client.force_login(self.alice)

        response = self.client.get(self.list_url, {"q": "laptop", "severity": "critical", "status": "open"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alice laptop compromised")
