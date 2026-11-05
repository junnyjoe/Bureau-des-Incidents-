from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View

from .audit import get_client_ip, record_audit_event
from .models import AuditEvent, UserTOTPDevice
from .permissions import is_administrator, is_analyst
from .ratelimit import is_ip_locked, record_login_failure, record_login_success, reset_rate_limit
from .totp import generate_totp_secret, get_totp_uri, verify_totp_code


class RateLimitedLoginView(LoginView):
    """
    Hardened LoginView with defense against brute-force and credential-stuffing attacks.
    - Limits failed login attempts per client IP.
    - Emits HTTP 429 (Too Many Requests) with explicit cooldown upon lockout.
    - Redirects privileged accounts (Analysts and Administrators) to Two-Factor Authentication.
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
        ip = get_client_ip(self.request)
        if ip:
            reset_rate_limit(ip)

        # Check if privileged account requires Two-Factor Authentication (2FA)
        two_factor_enforced = getattr(settings, "TWO_FACTOR_ENFORCED", True)
        requires_2fa = two_factor_enforced and (is_administrator(user) or is_analyst(user))

        if requires_2fa:
            UserTOTPDevice.objects.get_or_create(
                user=user,
                defaults={"secret": generate_totp_secret()},
            )
            self.request.session["pre_2fa_user_id"] = user.pk
            self.request.session["pre_2fa_next"] = self.get_success_url()
            return redirect("two_factor_verify")

        # Standard reporter login without 2FA
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


class TwoFactorVerifyView(View):
    """
    Two-Factor Authentication (TOTP, RFC 6238) verification view.
    Enforces secondary verification code check for Analysts and Administrators.
    """
    template_name = "registration/two_factor_verify.html"

    def dispatch(self, request, *args, **kwargs):
        user_id = request.session.get("pre_2fa_user_id")
        if not user_id:
            return redirect("login")
        return super().dispatch(request, *args, **kwargs)

    def _get_user_and_device(self, request):
        user_id = request.session.get("pre_2fa_user_id")
        User = get_user_model()
        user = get_object_or_404(User, pk=user_id)
        device, _ = UserTOTPDevice.objects.get_or_create(
            user=user,
            defaults={"secret": generate_totp_secret()},
        )
        return user, device

    def get(self, request):
        user, device = self._get_user_and_device(request)
        context = {
            "user_obj": user,
            "device": device,
            "is_confirmed": device.is_confirmed,
            "totp_uri": get_totp_uri(device.secret, user.username),
        }
        return render(request, self.template_name, context)

    def post(self, request):
        user, device = self._get_user_and_device(request)
        code = request.POST.get("code", "").strip()

        # Check rate limiting for TOTP submission
        ip = get_client_ip(request)
        is_locked, remaining = is_ip_locked(ip)
        if is_locked:
            context = {
                "user_obj": user,
                "device": device,
                "is_confirmed": device.is_confirmed,
                "totp_uri": get_totp_uri(device.secret, user.username),
                "error": f"Too many failed attempts. Your IP has been temporarily locked for security. Please try again in {remaining} seconds.",
            }
            return render(request, self.template_name, context, status=429)

        if verify_totp_code(device.secret, code):
            if not device.is_confirmed:
                device.is_confirmed = True
            device.last_verified_at = timezone.now()
            device.save(update_fields=["is_confirmed", "last_verified_at"])

            # Complete user login session
            auth.login(request, user)
            record_login_success(request, user)
            record_audit_event(
                action=AuditEvent.Action.TWO_FACTOR_VERIFIED,
                request=request,
                user=user,
                details=f"Two-factor authentication (TOTP) successfully verified for {user.username}.",
            )

            next_url = request.session.pop("pre_2fa_next", None) or reverse(settings.LOGIN_REDIRECT_URL)
            request.session.pop("pre_2fa_user_id", None)
            return redirect(next_url)

        # Invalid verification code
        record_login_failure(request, username=user.username)
        record_audit_event(
            action=AuditEvent.Action.TWO_FACTOR_FAILED,
            request=request,
            user=user,
            details=f"Invalid 2FA verification code submitted for {user.username}.",
        )
        context = {
            "user_obj": user,
            "device": device,
            "is_confirmed": device.is_confirmed,
            "totp_uri": get_totp_uri(device.secret, user.username),
            "error": "Invalid verification code. Please check your authenticator application and try again.",
        }
        return render(request, self.template_name, context, status=400)
