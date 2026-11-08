from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from incidents.admin import IncidentDeskUserCreationForm
from incidents.permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS

User = get_user_model()


class AdminRoleIntegrationTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            username="admin_super",
            email="admin@example.com",
            password="AdminSuperPassword123!",
        )
        self.client.force_login(self.admin_user)

    def test_creation_form_assigns_analyst_role(self):
        form_data = {
            "username": "analyst_sam",
            "email": "sam@example.com",
            "first_name": "Sam",
            "last_name": "Altman",
            "platform_role": "analyst",
            "password1": "ComplexPass123!#",
            "password2": "ComplexPass123!#",
        }
        form = IncidentDeskUserCreationForm(data=form_data)
        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertEqual(user.username, "analyst_sam")
        self.assertTrue(user.groups.filter(name=ROLE_ANALYSTS).exists())
        self.assertFalse(user.groups.filter(name=ROLE_ADMINISTRATORS).exists())

    def test_creation_form_assigns_administrator_role(self):
        form_data = {
            "username": "admin_app",
            "email": "app_admin@example.com",
            "platform_role": "administrator",
            "password1": "ComplexPass123!#",
            "password2": "ComplexPass123!#",
        }
        form = IncidentDeskUserCreationForm(data=form_data)
        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertTrue(user.groups.filter(name=ROLE_ADMINISTRATORS).exists())
        self.assertFalse(user.groups.filter(name=ROLE_ANALYSTS).exists())

    def test_admin_user_changelist_view_renders_role_column(self):
        User.objects.create_user(username="reporter_rep", password="ComplexPass123!#")
        response = self.client.get(reverse("admin:auth_user_changelist"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Rôle Incident Desk")
        self.assertContains(response, "Superadmin")
        self.assertContains(response, "Déclarant")

    def test_admin_user_add_view_renders_platform_role_choices(self):
        response = self.client.get(reverse("admin:auth_user_add"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Rôle Incident Desk")
        self.assertContains(response, "Analyste (Analyst)")
        self.assertContains(response, "Déclarant (Reporter)")
        self.assertContains(response, "Administrateur applicatif")
