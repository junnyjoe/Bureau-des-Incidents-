import time
from django.conf import settings
from django.contrib import auth, messages
from django.shortcuts import redirect
from django.urls import reverse


class SessionIdleTimeoutMiddleware:
    """
    Terminates inactive user sessions after a defined inactivity threshold.
    - Privileged roles (analysts, administrators): default 15 minutes (900s).
    - Standard reporters: default 30 minutes (1800s).
    - On timeout: logs out the user, flushes session, logs audit event,
      and redirects to the login screen with an explanatory notice.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if hasattr(request, "user") and request.user.is_authenticated:
            now = time.time()
            last_activity = request.session.get("_last_activity")

            from incidents.permissions import is_administrator, is_analyst
            if is_administrator(request.user) or is_analyst(request.user):
                timeout = getattr(settings, "SESSION_IDLE_TIMEOUT_PRIVILEGED", 900)
            else:
                timeout = getattr(settings, "SESSION_IDLE_TIMEOUT", 1800)

            if last_activity and (now - last_activity > timeout):
                from incidents.audit import record_audit_event
                from incidents.models import AuditEvent

                username = request.user.username
                record_audit_event(
                    action=AuditEvent.Action.LOGOUT,
                    request=request,
                    user=request.user,
                    details=f"Session expired due to inactivity ({int(now - last_activity)}s > {timeout}s)",
                )
                auth.logout(request)
                request.session.flush()
                messages.info(request, "Your session has expired due to inactivity. Please sign in again.")
                return redirect(f"{reverse('login')}?expired=1")

            request.session["_last_activity"] = now

        return self.get_response(request)


class ResponsePolicyMiddleware:
    """A small, explicit policy for the server-rendered starter."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # The course UI has no inline scripts/styles or third-party assets.
        # Django admin has its own assets/inline behavior; review its CSP separately.
        if not request.path.startswith("/admin/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'"
            )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Never let a shared cache retain private/authentication pages.
        if request.user.is_authenticated or request.path.startswith("/accounts/"):
            response.headers["Cache-Control"] = "no-store, private"
        return response

