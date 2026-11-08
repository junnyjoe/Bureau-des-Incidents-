from django import forms
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from django.contrib.auth.models import Group
from django.utils.html import format_html

from .models import AuditEvent, Comment, Incident
from .permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS

User = get_user_model()


class IncidentDeskUserCreationForm(UserCreationForm):
    ROLE_CHOICES = [
        ("reporter", "👤 Déclarant (Reporter) — Signale et suit ses propres incidents"),
        ("analyst", "🔍 Analyste (Analyst) — Traite, prend en charge et résout les incidents"),
        ("administrator", "🛡️ Administrateur applicatif — Supervise et assigne tous les incidents"),
    ]

    platform_role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        initial="reporter",
        label="Rôle Incident Desk",
        widget=forms.RadioSelect,
        help_text="Attribution automatique du groupe et des permissions associées.",
    )
    email = forms.EmailField(
        required=False,
        label="Adresse email",
        help_text="Optionnel mais recommandé pour les notifications.",
    )
    first_name = forms.CharField(
        max_length=150,
        required=False,
        label="Prénom",
    )
    last_name = forms.CharField(
        max_length=150,
        required=False,
        label="Nom",
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "first_name", "last_name", "email")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data.get("email", "")
        user.first_name = self.cleaned_data.get("first_name", "")
        user.last_name = self.cleaned_data.get("last_name", "")
        if commit:
            user.save()
            self.save_m2m()
            role = self.cleaned_data.get("platform_role")
            analysts_group, _ = Group.objects.get_or_create(name=ROLE_ANALYSTS)
            admins_group, _ = Group.objects.get_or_create(name=ROLE_ADMINISTRATORS)
            user.groups.remove(analysts_group, admins_group)
            if role == "analyst":
                user.groups.add(analysts_group)
            elif role == "administrator":
                user.groups.add(admins_group)
        return user


class IncidentDeskUserChangeForm(UserChangeForm):
    ROLE_CHOICES = [
        ("reporter", "👤 Déclarant (Reporter) — Signale et suit ses propres incidents"),
        ("analyst", "🔍 Analyste (Analyst) — Traite, prend en charge et résout les incidents"),
        ("administrator", "🛡️ Administrateur applicatif — Supervise et assigne tous les incidents"),
    ]

    platform_role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        label="Rôle Incident Desk",
        widget=forms.RadioSelect,
        help_text="Modifie l'appartenance aux groupes Analysts / Administrators.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            if self.instance.groups.filter(name=ROLE_ADMINISTRATORS).exists():
                self.fields["platform_role"].initial = "administrator"
            elif self.instance.groups.filter(name=ROLE_ANALYSTS).exists():
                self.fields["platform_role"].initial = "analyst"
            else:
                self.fields["platform_role"].initial = "reporter"


class PlatformRoleFilter(admin.SimpleListFilter):
    title = "Rôle Incident Desk"
    parameter_name = "platform_role"

    def lookups(self, request, model_admin):
        return [
            ("superuser", "👑 Superadministrateur"),
            ("administrator", "🛡️ Administrateur"),
            ("analyst", "🔍 Analyste"),
            ("reporter", "👤 Déclarant"),
        ]

    def queryset(self, request, queryset):
        if self.value() == "superuser":
            return queryset.filter(is_superuser=True)
        if self.value() == "administrator":
            return queryset.filter(groups__name=ROLE_ADMINISTRATORS, is_superuser=False)
        if self.value() == "analyst":
            return queryset.filter(groups__name=ROLE_ANALYSTS, is_superuser=False)
        if self.value() == "reporter":
            return queryset.exclude(groups__name__in=[ROLE_ADMINISTRATORS, ROLE_ANALYSTS]).filter(is_superuser=False)
        return queryset


class IncidentDeskUserAdmin(BaseUserAdmin):
    add_form = IncidentDeskUserCreationForm
    form = IncidentDeskUserChangeForm

    add_fieldsets = (
        (
            "Créer un utilisateur Incident Desk avec son rôle",
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "first_name",
                    "last_name",
                    "email",
                    "platform_role",
                    "password1",
                    "password2",
                ),
            },
        ),
    )

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (
            "Rôle sur la plateforme Incident Desk",
            {
                "fields": ("platform_role",),
                "description": "Sélectionnez le rôle de l'utilisateur pour lui attribuer automatiquement ses permissions SOC / incidents.",
            },
        ),
        ("Informations personnelles", {"fields": ("first_name", "last_name", "email")}),
        (
            "Permissions avancées",
            {
                "classes": ("collapse",),
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        ("Dates importantes", {"classes": ("collapse",), "fields": ("last_login", "date_joined")}),
    )

    list_display = [
        "username",
        "email",
        "first_name",
        "last_name",
        "get_platform_role",
        "is_active",
        "is_staff",
    ]
    list_filter = [PlatformRoleFilter, "is_active", "is_staff", "is_superuser"]
    actions = ["make_reporter", "make_analyst", "make_administrator"]

    @admin.display(description="Rôle Incident Desk")
    def get_platform_role(self, obj):
        if obj.is_superuser:
            return format_html(
                '<span style="background-color:#dbeafe;color:#1e40af;padding:3px 10px;border-radius:12px;font-weight:600;font-size:12px;">👑 Superadmin</span>'
            )
        if obj.groups.filter(name=ROLE_ADMINISTRATORS).exists():
            return format_html(
                '<span style="background-color:#fef3c7;color:#92400e;padding:3px 10px;border-radius:12px;font-weight:600;font-size:12px;">🛡️ Administrateur</span>'
            )
        if obj.groups.filter(name=ROLE_ANALYSTS).exists():
            return format_html(
                '<span style="background-color:#e0e7ff;color:#3730a3;padding:3px 10px;border-radius:12px;font-weight:600;font-size:12px;">🔍 Analyste</span>'
            )
        return format_html(
            '<span style="background-color:#f3f4f6;color:#4b5563;padding:3px 10px;border-radius:12px;font-weight:500;font-size:12px;">👤 Déclarant</span>'
        )

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        if "platform_role" in form.cleaned_data:
            role = form.cleaned_data["platform_role"]
            user = form.instance
            analysts_group, _ = Group.objects.get_or_create(name=ROLE_ANALYSTS)
            admins_group, _ = Group.objects.get_or_create(name=ROLE_ADMINISTRATORS)
            user.groups.remove(analysts_group, admins_group)
            if role == "analyst":
                user.groups.add(analysts_group)
            elif role == "administrator":
                user.groups.add(admins_group)

    @admin.action(description="Assigner le rôle Déclarant (Reporter)")
    def make_reporter(self, request, queryset):
        analysts = Group.objects.filter(name=ROLE_ANALYSTS).first()
        admins = Group.objects.filter(name=ROLE_ADMINISTRATORS).first()
        for user in queryset:
            if analysts:
                user.groups.remove(analysts)
            if admins:
                user.groups.remove(admins)
        self.message_user(request, f"Rôle Déclarant assigné à {queryset.count()} utilisateur(s).")

    @admin.action(description="Assigner le rôle Analyste (Analyst)")
    def make_analyst(self, request, queryset):
        analysts, _ = Group.objects.get_or_create(name=ROLE_ANALYSTS)
        admins = Group.objects.filter(name=ROLE_ADMINISTRATORS).first()
        for user in queryset:
            if admins:
                user.groups.remove(admins)
            user.groups.add(analysts)
        self.message_user(request, f"Rôle Analyste assigné à {queryset.count()} utilisateur(s).")

    @admin.action(description="Assigner le rôle Administrateur applicatif")
    def make_administrator(self, request, queryset):
        admins, _ = Group.objects.get_or_create(name=ROLE_ADMINISTRATORS)
        analysts = Group.objects.filter(name=ROLE_ANALYSTS).first()
        for user in queryset:
            if analysts:
                user.groups.remove(analysts)
            user.groups.add(admins)
        self.message_user(request, f"Rôle Administrateur assigné à {queryset.count()} utilisateur(s).")


# Unregister default UserAdmin and register our custom IncidentDeskUserAdmin
if User in admin.site._registry:
    admin.site.unregister(User)

admin.site.register(User, IncidentDeskUserAdmin)


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ["id", "reference", "title", "severity", "status", "created_by", "assigned_to", "created_at"]
    list_filter = ["status", "severity", "assigned_to", "created_at"]
    list_select_related = ["created_by", "assigned_to"]
    search_fields = ["title", "created_by__username", "assigned_to__username"]
    readonly_fields = ["created_by", "created_at"]

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ["id", "incident", "author", "created_at"]
    list_filter = ["created_at"]
    search_fields = ["body", "author__username", "incident__title"]
    readonly_fields = ["created_at"]


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ["id", "action", "username_snapshot", "ip_address", "incident", "created_at"]
    list_filter = ["action", "created_at"]
    search_fields = ["username_snapshot", "ip_address", "details"]
    readonly_fields = ["action", "user", "username_snapshot", "ip_address", "incident", "details", "created_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
