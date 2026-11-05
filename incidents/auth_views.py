from django.contrib.auth.views import LoginView
from django.http import HttpResponse
from .audit import get_client_ip
from .ratelimit import is_ip_locked, record_login_failure, record_login_success


class RateLimitedLoginView(LoginView):
    """
    Hardened LoginView with defense against brute-force and credential-stuffing attacks.
    - Limits failed login attempts per client IP.
    - Emits HTTP 429 (Too Many Requests) with explicit cooldown upon lockout.
    - Emits immutable security AuditEvent records for successful and failed attempts.
    """
    def dispatch(self, request, *args, **kwargs):
        if request.method == "POST":
            ip = get_client_ip(request)
            is_locked, remaining = is_ip_locked(ip)
            if is_locked:
                form = self.get_form()
                context = self.get_context_data(form=form)
                context["lockout_error"] = (
                    f"Too many failed login attempts. Your IP ({ip}) has been temporarily locked for security. "
                    f"Please try again in {remaining} second{'s' if remaining != 1 else ''}."
                )
                response = self.render_to_response(context)
                response.status_code = 429
                return response
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.get_user()
        record_login_success(self.request, user)
        return super().form_valid(form)

    def form_invalid(self, form):
        username = self.request.POST.get("username", "").strip()
        is_locked, remaining = record_login_failure(self.request, username=username)
        if is_locked:
            context = self.get_context_data(form=form)
            ip = get_client_ip(self.request) or "unknown"
            context["lockout_error"] = (
                f"Too many failed login attempts. Your IP ({ip}) has been temporarily locked for security. "
                f"Please try again in {remaining} second{'s' if remaining != 1 else ''}."
            )
            response = self.render_to_response(context)
            response.status_code = 429
            return response
        return super().form_invalid(form)
