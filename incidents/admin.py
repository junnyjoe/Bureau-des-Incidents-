from django.contrib import admin
from .models import AuditEvent, Comment, Incident

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
