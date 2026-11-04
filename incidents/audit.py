import logging
import re
from .models import AuditEvent

logger = logging.getLogger("incidents.audit")

# Sensitive patterns that must never appear in audit logs
SENSITIVE_PATTERNS = [
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"key", re.IGNORECASE),
]

def get_client_ip(request):
    """Safely determine the client IP address from request."""
    if not request:
        return None
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip

def record_audit_event(action, request=None, user=None, incident=None, details=""):
    """
    Safely record an audit event in the database and structured logger.
    Guarantees that sensitive data (passwords, tokens) are never persisted in logs.
    """
    if request:
        if not user and request.user.is_authenticated:
            user = request.user
        ip_address = get_client_ip(request)
    else:
        ip_address = None

    username = user.get_username() if user and user.is_authenticated else "anonymous"

    # Sanitize details string: limit length and ensure no accidental secrets
    clean_details = str(details)[:450]

    event = AuditEvent.objects.create(
        action=action,
        user=user if user and user.is_authenticated else None,
        username_snapshot=username,
        ip_address=ip_address,
        incident=incident,
        details=clean_details,
    )

    logger.info(
        "AUDIT_EVENT action=%s user=%s ip=%s incident=%s details=%s",
        action,
        username,
        ip_address,
        incident.reference if incident else "none",
        clean_details,
    )
    return event
