from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from incidents.models import Incident

class Command(BaseCommand):
    help = "Seed only the isolated security_lab database with public synthetic fixtures."

    @transaction.atomic
    def handle(self, *args, **kwargs):
        if not getattr(settings, "TRAINING_MODE", False) or settings.SETTINGS_MODULE != "config.settings.security_lab":
            raise CommandError("Use only config.settings.security_lab for this deliberately insecure fixture.")
        for name, title, description in [
            ("lab-alice", "Alice training laptop", "ALICE_SYNTHETIC_RECORD: only Alice should see this in the application."),
            ("lab-bob", "Bob training network", "BOB_PRIVATE_FIXTURE: synthetic data used to prove cross-owner disclosure."),
        ]:
            user, created = get_user_model().objects.get_or_create(username=name)
            if created:
                user.set_password("local-training-only")
                user.save()
            Incident.objects.get_or_create(created_by=user, title=title, defaults={"description":description})
        self.stdout.write("Local fixtures ready: lab-alice / lab-bob, password local-training-only. Never use these accounts elsewhere.")
