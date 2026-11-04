from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from django.db import models

class Incident(models.Model):
    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        IN_PROGRESS = "in_progress", "In Progress"
        RESOLVED = "resolved", "Resolved"
        CLOSED = "closed", "Closed"

    ALLOWED_TRANSITIONS = {
        Status.OPEN: {Status.OPEN, Status.IN_PROGRESS, Status.CLOSED},
        Status.IN_PROGRESS: {Status.IN_PROGRESS, Status.RESOLVED, Status.CLOSED, Status.OPEN},
        Status.RESOLVED: {Status.RESOLVED, Status.CLOSED, Status.IN_PROGRESS},
        Status.CLOSED: {Status.CLOSED, Status.OPEN},
    }

    title = models.CharField(max_length=150, validators=[MinLengthValidator(3)])
    description = models.TextField(max_length=5000, validators=[MinLengthValidator(10)])
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.MEDIUM,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.OPEN,
    )
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="incidents")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["created_by", "-created_at"], name="incident_owner_created_idx"),
            models.Index(fields=["status", "-created_at"], name="incident_status_created_idx"),
        ]

    @property
    def reference(self):
        return f"INC-{self.pk:04d}"

    def can_transition_to(self, new_status):
        allowed = self.ALLOWED_TRANSITIONS.get(self.status, {self.status})
        return new_status in allowed

    def clean(self):
        super().clean()
        if self.pk:
            original = Incident.objects.filter(pk=self.pk).values("status").first()
            if original and self.status != original["status"]:
                allowed = self.ALLOWED_TRANSITIONS.get(original["status"], set())
                if self.status not in allowed:
                    raise ValidationError(
                        {"status": f"Invalid state transition from '{original['status']}' to '{self.status}'."}
                    )

    def transition_to(self, new_status):
        self.status = new_status
        self.clean()
        self.save(update_fields=["status"])

    def __str__(self):
        return f"{self.reference}: {self.title} [{self.get_status_display()}]"
