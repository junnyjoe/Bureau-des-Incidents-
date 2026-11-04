from django.db.models import Q
from .models import Incident

ROLE_ADMINISTRATORS = "Administrators"
ROLE_ANALYSTS = "Analysts"

def is_administrator(user):
    """
    Check if a user has application-level administrator privileges.
    Do not equate ordinary business administrators automatically with Django superusers,
    though superusers have administrative access by default.
    """
    if not user or not user.is_authenticated:
        return False
    return user.is_superuser or user.groups.filter(name=ROLE_ADMINISTRATORS).exists()

def is_analyst(user):
    """
    Check if a user belongs to the Analysts group.
    """
    if not user or not user.is_authenticated:
        return False
    return user.groups.filter(name=ROLE_ANALYSTS).exists()

def get_visible_incidents_for_user(user):
    """
    Return queryset of incidents visible to the given user based on role policy:
    - Administrators: can view all incidents.
    - Analysts: can view incidents explicitly assigned to them or created by them.
    - Reporters: can view only incidents they created.
    """
    if not user or not user.is_authenticated:
        return Incident.objects.none()
    if is_administrator(user):
        return Incident.objects.all()
    if is_analyst(user):
        return Incident.objects.filter(Q(assigned_to=user) | Q(created_by=user))
    return Incident.objects.filter(created_by=user)

def can_assign_analyst(user, incident):
    """Only administrators can assign or reassign analysts."""
    return is_administrator(user)

def can_update_incident_status(user, incident):
    """Administrators and the assigned analyst can update status."""
    if not user or not user.is_authenticated:
        return False
    if is_administrator(user):
        return True
    if is_analyst(user) and incident.assigned_to_id == user.pk:
        return True
    return False
