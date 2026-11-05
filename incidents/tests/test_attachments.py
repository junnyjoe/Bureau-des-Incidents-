import hashlib
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from incidents.models import AuditEvent, Incident, IncidentAttachment


class AttachmentSecurityTests(TestCase):
    """
    Automated security tests for evidence attachments.
    Verifies:
    - Magic bytes validation and MIME-type spoofing defense.
    - Blocking of executable extensions (web shells, scripts).
    - Cryptographic SHA-256 forensic hashing.
    - Strict cross-tenant access denial on download endpoints (BOLA/IDOR prevention).
    - Defensive headers on downloads (X-Content-Type-Options: nosniff).
    """

    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user(username="alice_attach", password="ValidPassword123!")
        self.bob = User.objects.create_user(username="bob_attach", password="ValidPassword123!")

        self.incident_alice = Incident.objects.create(
            title="Alice forensic incident",
            description="Alice synthetic incident requiring forensic proof.",
            created_by=self.alice,
        )
        self.incident_bob = Incident.objects.create(
            title="Bob forensic incident",
            description="Bob private incident.",
            created_by=self.bob,
        )

        self.upload_url = reverse("incidents:upload_attachment", args=[self.incident_alice.pk])

    def test_valid_text_log_upload_succeeds_with_sha256(self):
        self.client.force_login(self.alice)

        file_content = b"Nov  5 14:00:00 server sshd[1234]: Failed password for root"
        expected_hash = hashlib.sha256(file_content).hexdigest()

        uploaded = SimpleUploadedFile("auth.log", file_content, content_type="text/plain")
        response = self.client.post(self.upload_url, {"file": uploaded})

        self.assertRedirects(response, reverse("incidents:detail", args=[self.incident_alice.pk]))
        self.assertEqual(self.incident_alice.attachments.count(), 1)

        att = self.incident_alice.attachments.first()
        self.assertEqual(att.original_filename, "auth.log")
        self.assertEqual(att.sha256_hash, expected_hash)
        self.assertEqual(att.file_size, len(file_content))
        self.assertEqual(att.uploaded_by, self.alice)

        # Audit event verification
        audit = AuditEvent.objects.filter(
            action=AuditEvent.Action.ATTACHMENT_UPLOADED,
            incident=self.incident_alice,
        ).first()
        self.assertIsNotNone(audit)
        self.assertIn("auth.log", audit.details)

    def test_valid_png_image_upload_succeeds(self):
        self.client.force_login(self.alice)

        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        uploaded = SimpleUploadedFile("screenshot.png", png_bytes, content_type="image/png")
        response = self.client.post(self.upload_url, {"file": uploaded})

        self.assertRedirects(response, reverse("incidents:detail", args=[self.incident_alice.pk]))
        self.assertEqual(self.incident_alice.attachments.count(), 1)

    def test_dangerous_file_extension_is_rejected(self):
        self.client.force_login(self.alice)

        webshell = SimpleUploadedFile("shell.php", b"<?php phpinfo(); ?>", content_type="application/x-php")
        response = self.client.post(self.upload_url, {"file": webshell})

        self.assertEqual(self.incident_alice.attachments.count(), 0)

    def test_mime_spoofing_rejected_by_magic_bytes_inspection(self):
        """A PHP script disguised with a .png extension must be caught by magic bytes inspection."""
        self.client.force_login(self.alice)

        disguised_file = SimpleUploadedFile("payload.png", b"<?php system($_GET['c']); ?>", content_type="image/png")
        response = self.client.post(self.upload_url, {"file": disguised_file})

        self.assertEqual(self.incident_alice.attachments.count(), 0)

    def test_download_enforces_scoping_and_security_headers(self):
        # Alice uploads a valid log
        self.client.force_login(self.alice)
        uploaded = SimpleUploadedFile("firewall.log", b"DROP input from 192.0.2.1", content_type="text/plain")
        self.client.post(self.upload_url, {"file": uploaded})
        att = self.incident_alice.attachments.first()

        download_url = reverse("incidents:download_attachment", args=[att.pk])

        # 1. Alice (owner) downloads her attachment
        dl_response = self.client.get(download_url)
        self.assertEqual(dl_response.status_code, 200)
        self.assertIn("attachment;", dl_response["Content-Disposition"])
        self.assertEqual(dl_response["X-Content-Type-Options"], "nosniff")

        # 2. Bob attempts cross-tenant download of Alice's attachment
        self.client.force_login(self.bob)
        bob_response = self.client.get(download_url)
        self.assertEqual(bob_response.status_code, 404)
