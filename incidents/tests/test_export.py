import csv
import json
from io import StringIO
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from incidents.models import AuditEvent, Incident
from incidents.views import sanitize_csv_cell


class ExportSecurityTests(TestCase):
    """
    Automated tests for CSV and JSON incident export.
    Verifies:
    - Protection against CSV / Formula Injection (CWE-1236).
    - Scope enforcement (users can only export incidents in their authorized scope).
    - Audit event generation on data export.
    """

    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user(username="alice_export", password="ValidPassword123!")
        self.bob = User.objects.create_user(username="bob_export", password="ValidPassword123!")

        # Incident with formula injection payload in title and description
        self.malicious_incident = Incident.objects.create(
            title="=cmd|' /C calc'!A0",
            description="-2+3+cmd|' /C notepad'!A0",
            severity=Incident.Severity.HIGH,
            status=Incident.Status.OPEN,
            created_by=self.alice,
        )

        self.bob_incident = Incident.objects.create(
            title="Bob confidential secret report",
            description="Bob proprietary details.",
            severity=Incident.Severity.CRITICAL,
            created_by=self.bob,
        )

    def test_sanitize_csv_cell_neutralizes_formula_triggers(self):
        """Dangerous spreadsheet formula characters must be safely escaped with a single quote."""
        self.assertEqual(sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(sanitize_csv_cell("+cmd|calc"), "'+cmd|calc")
        self.assertEqual(sanitize_csv_cell("-5+2"), "'-5+2")
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("\tTABBED"), "'\tTABBED")

        # Harmless text is left untouched
        self.assertEqual(sanitize_csv_cell("Standard report title"), "Standard report title")
        self.assertEqual(sanitize_csv_cell(""), "")
        self.assertEqual(sanitize_csv_cell(None), "")

    def test_csv_export_escapes_formulas_and_scopes_data(self):
        self.client.force_login(self.alice)

        response = self.client.get(reverse("incidents:export_csv"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn("attachment;", response["Content-Disposition"])

        content = response.content.decode("utf-8")
        reader = csv.reader(StringIO(content))
        rows = list(reader)

        # Header row
        self.assertEqual(rows[0][0], "Reference")
        self.assertEqual(rows[0][1], "Title")

        # Data rows
        self.assertEqual(len(rows), 2)  # 1 header + 1 incident for Alice
        data_row = rows[1]

        # Neutralized formula payload in Title and Description
        self.assertTrue(data_row[1].startswith("'="))
        self.assertTrue(data_row[2].startswith("'-"))

        # Bob's incident must NOT be present
        self.assertNotIn("Bob confidential secret report", content)

        # Audit event verification
        audit_event = AuditEvent.objects.filter(
            action=AuditEvent.Action.DATA_EXPORTED,
            user=self.alice,
        ).first()
        self.assertIsNotNone(audit_event)
        self.assertIn("CSV", audit_event.details)

    def test_json_export_returns_valid_scoped_json(self):
        self.client.force_login(self.alice)

        response = self.client.get(reverse("incidents:export_json"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")

        data = json.loads(response.content.decode("utf-8"))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["reference"], self.malicious_incident.reference)
        self.assertNotIn("Bob confidential secret report", response.content.decode("utf-8"))
