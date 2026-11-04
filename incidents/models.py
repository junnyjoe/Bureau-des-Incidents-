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
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="incidents",
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_incidents",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["created_by", "-created_at"], name="incident_owner_created_idx"),
            models.Index(fields=["status", "-created_at"], name="incident_status_created_idx"),
            models.Index(fields=["assigned_to", "-created_at"], name="incident_assigned_created_idx"),
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


class Comment(models.Model):
    """
    Plain-text comment attached to an incident.
    Must always be treated and rendered as inert plain-text (anti-stored XSS).
    """
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="incident_comments")
    body = models.TextField(max_length=2000, validators=[MinLengthValidator(2)])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "pk"]
        indexes = [
            models.Index(fields=["incident", "created_at"], name="comment_incident_created_idx"),
        ]

    def __str__(self):
        return f"Comment by {self.author.username} on {self.incident.reference} at {self.created_at}"


class AuditEvent(models.Model):
    """
    Application security audit log.
    Records critical events without storing sensitive data (no passwords, tokens or secrets).
    """
    class Action(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Login Success"
        LOGIN_FAILED = "login_failed", "Login Failed"
        LOGOUT = "logout", "Logout"
        STATUS_CHANGE = "status_change", "Status Change"
        ASSIGNMENT = "assignment", "Assignment Changed"
        COMMENT_ADDED = "comment_added", "Comment Added"
        INCIDENT_CREATED = "incident_created", "Incident Created"

    action = models.CharField(max_length=40, choices=Action.choices)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    username_snapshot = models.CharField(max_length=150, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, null=True, blank=True, related_name="audit_events")
    details = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["action", "-created_at"], name="audit_action_created_idx"),
            models.Index(fields=["incident", "-created_at"], name="audit_incident_created_idx"),
        ]

    def __str__(self):
        return f"[{self.created_at}] {self.get_action_display()} - User: {self.username_snapshot} - IP: {self.ip_address}"
