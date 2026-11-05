import time
from django.conf import settings
from django.core.cache import cache
from .audit import get_client_ip, record_audit_event
from .models import AuditEvent

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_SECONDS = 300  # 5 minutes
DEFAULT_WINDOW_SECONDS = 300   # 5 minutes


def _get_max_attempts():
    return getattr(settings, "LOGIN_RATELIMIT_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS)


def _get_lockout_seconds():
    return getattr(settings, "LOGIN_RATELIMIT_LOCKOUT_SECONDS", DEFAULT_LOCKOUT_SECONDS)


def _get_window_seconds():
    return getattr(settings, "LOGIN_RATELIMIT_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS)


def _make_attempts_key(ip):
    return f"login_attempts_{ip}"


def _make_lockout_key(ip):
    return f"login_lockout_{ip}"


def is_ip_locked(ip):
    """
    Check if the given IP address is currently locked out.
    Returns (is_locked: bool, remaining_seconds: int).
    """
    if not ip:
        return False, 0
    lockout_key = _make_lockout_key(ip)
    expires_at = cache.get(lockout_key)
    if expires_at:
        remaining = max(1, int(expires_at - time.time()))
        return True, remaining
    return False, 0


def record_login_failure(request, username=""):
    """
    Record a failed login attempt for the request's IP.
    Returns (is_locked: bool, remaining_seconds: int).
    """
    ip = get_client_ip(request) or "unknown"
    attempts_key = _make_attempts_key(ip)
    max_attempts = _get_max_attempts()
    lockout_seconds = _get_lockout_seconds()
    window_seconds = _get_window_seconds()

    clean_user = (username or "unknown")[:150]

    # Increment failure counter
    try:
        attempts = cache.get(attempts_key, 0) + 1
        cache.set(attempts_key, attempts, timeout=window_seconds)
    except Exception:
        attempts = 1

    if attempts >= max_attempts:
        # Lockout the IP
        lockout_key = _make_lockout_key(ip)
        expires_at = time.time() + lockout_seconds
        cache.set(lockout_key, expires_at, timeout=lockout_seconds)

        record_audit_event(
            action=AuditEvent.Action.LOGIN_FAILED,
            request=request,
            details=f"Rate limit exceeded: IP {ip} locked out for {lockout_seconds}s after {attempts} failed attempts (username: {clean_user})",
        )
        return True, lockout_seconds

    record_audit_event(
        action=AuditEvent.Action.LOGIN_FAILED,
        request=request,
        details=f"Failed login attempt ({attempts}/{max_attempts}) for username '{clean_user}'",
    )
    return False, 0


def record_login_success(request, user):
    """
    Clear failed attempt counters for the IP and record an audit log event.
    """
    ip = get_client_ip(request)
    if ip:
        reset_rate_limit(ip)

    record_audit_event(
        action=AuditEvent.Action.LOGIN_SUCCESS,
        request=request,
        user=user,
        details=f"Successful authentication for {user.username}",
    )


def reset_rate_limit(ip):
    """Reset rate limiting counters and lockouts for a given IP."""
    if not ip:
        return
    cache.delete(_make_attempts_key(ip))
    cache.delete(_make_lockout_key(ip))
