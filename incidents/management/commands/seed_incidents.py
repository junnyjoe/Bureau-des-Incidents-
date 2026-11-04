from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from incidents.models import Incident

class Command(BaseCommand):
    help = "Add two synthetic incidents to an existing local user (idempotent; no passwords created)."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)

    @transaction.atomic
    def handle(self, *args, **options):
        from django.conf import settings
        if not settings.DEBUG:
            raise CommandError("Demo seeding is local-only. Create production records through the app.")
        try:
            user = get_user_model().objects.get(username=options["username"])
        except get_user_model().DoesNotExist as exc:
            raise CommandError("Create this user first using createsuperuser or Django admin.") from exc
        for title, description in [
            ("Training workstation unavailable", "Synthetic report: a training workstation cannot access the demonstration network."),
            ("Unexpected test notification", "Synthetic report: a demonstration notification arrived outside the planned exercise."),
        ]:
            Incident.objects.get_or_create(created_by=user, title=title, defaults={"description": description})
        self.stdout.write(self.style.SUCCESS("Synthetic incidents are ready. No user credentials were created."))
