from django.urls import path
from .views import (
    IncidentAssignView,
    IncidentAttachmentDownloadView,
    IncidentAttachmentUploadView,
    IncidentCommentCreateView,
    IncidentCreateView,
    IncidentDetailView,
    IncidentExportCSVView,
    IncidentExportJSONView,
    IncidentListView,
    IncidentStatusUpdateView,
    SOCDashboardView,
)

app_name = "incidents"

urlpatterns = [
    path("", IncidentListView.as_view(), name="list"),
    path("dashboard/", SOCDashboardView.as_view(), name="dashboard"),
    path("incidents/export/csv/", IncidentExportCSVView.as_view(), name="export_csv"),
    path("incidents/export/json/", IncidentExportJSONView.as_view(), name="export_json"),
    path("incidents/new/", IncidentCreateView.as_view(), name="create"),
    path("incidents/<int:pk>/", IncidentDetailView.as_view(), name="detail"),
    path("incidents/<int:pk>/assign/", IncidentAssignView.as_view(), name="assign"),
    path("incidents/<int:pk>/status/", IncidentStatusUpdateView.as_view(), name="update_status"),
    path("incidents/<int:pk>/comment/", IncidentCommentCreateView.as_view(), name="add_comment"),
    path("incidents/<int:pk>/attachment/", IncidentAttachmentUploadView.as_view(), name="upload_attachment"),
    path("incidents/attachment/<int:attachment_id>/download/", IncidentAttachmentDownloadView.as_view(), name="download_attachment"),
]
