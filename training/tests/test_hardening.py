"""Acceptance gate: fails on the original vulnerability, passes after remediation."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from incidents.models import Incident

from unittest import skipUnless
from django.conf import settings

@skipUnless(getattr(settings, "TRAINING_MODE", False), "Run explicitly with config.settings.security_lab")
class SearchHardeningTests(TestCase):
    def setUp(self):
        self.alice = get_user_model().objects.create_user(username="test-alice", password="test-only")
        self.bob = get_user_model().objects.create_user(username="test-bob", password="test-only")
        Incident.objects.create(title="Alice laptop",description="ALICE_OWN_FIXTURE",created_by=self.alice)
        Incident.objects.create(title="Bob network",description="BOB_PRIVATE_FIXTURE",created_by=self.bob)
        self.client.force_login(self.alice)
        self.url = reverse("training-search")

    def test_normal_search_still_works(self):
        response=self.client.get(self.url,{"q":"laptop"})
        self.assertContains(response,"ALICE_OWN_FIXTURE")
        self.assertNotContains(response,"BOB_PRIVATE_FIXTURE")

    def test_empty_search_is_owner_scoped(self):
        response=self.client.get(self.url,{"q":""})
        self.assertContains(response,"ALICE_OWN_FIXTURE")
        self.assertNotContains(response,"BOB_PRIVATE_FIXTURE")

    def test_injected_boolean_does_not_disclose_another_owner(self):
        response=self.client.get(self.url,{"q":"%' OR 1=1 -- "})
        self.assertNotContains(response,"BOB_PRIVATE_FIXTURE")

    def test_quote_is_data_not_database_error(self):
        response=self.client.get(self.url,{"q":"'"})
        self.assertNotContains(response,"Training database error:")

    def test_anonymous_search_requires_login(self):
        self.client.logout()
        self.assertEqual(self.client.get(self.url,{"q":"laptop"}).status_code,302)
