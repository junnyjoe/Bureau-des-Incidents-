from django.urls import path
from .views import (
    IncidentAssignView,
    IncidentCreateView,
    IncidentDetailView,
    IncidentListView,
    IncidentStatusUpdateView,
)

app_name = "incidents"

urlpatterns = [
    path("", IncidentListView.as_view(), name="list"),
    path("incidents/new/", IncidentCreateView.as_view(), name="create"),
    path("incidents/<int:pk>/", IncidentDetailView.as_view(), name="detail"),
    path("incidents/<int:pk>/assign/", IncidentAssignView.as_view(), name="assign"),
    path("incidents/<int:pk>/status/", IncidentStatusUpdateView.as_view(), name="update_status"),
]
