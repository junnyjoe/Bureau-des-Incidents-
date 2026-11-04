from django.contrib import admin
from .models import Incident

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
