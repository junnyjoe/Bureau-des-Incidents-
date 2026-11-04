from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views import View
from django.views.generic import CreateView, DetailView, ListView

from .forms import IncidentAssignForm, IncidentForm, IncidentStatusUpdateForm
from .models import Incident
from .permissions import (
    can_assign_analyst,
    can_update_incident_status,
    get_visible_incidents_for_user,
    is_administrator,
    is_analyst,
)

class OwnedIncidentsMixin(LoginRequiredMixin):
    """
    Scope incidents visible to the signed-in user according to server-side role policy:
    - Administrators: all incidents
    - Analysts: assigned incidents + created incidents
    - Reporters: created incidents
    """
    def get_queryset(self):
        return get_visible_incidents_for_user(self.request.user)

class IncidentListView(OwnedIncidentsMixin, ListView):
    model = Incident
    template_name = "incidents/list.html"
    context_object_name = "incidents"
    paginate_by = 10

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["is_admin"] = is_administrator(self.request.user)
        context["is_analyst"] = is_analyst(self.request.user)
        return context

class IncidentDetailView(OwnedIncidentsMixin, DetailView):
    model = Incident
    template_name = "incidents/detail.html"
    context_object_name = "incident"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        incident = self.object
        user = self.request.user
        can_assign = can_assign_analyst(user, incident)
        can_update_status = can_update_incident_status(user, incident)
        context["can_assign"] = can_assign
        context["can_update_status"] = can_update_status
        if can_assign:
            context["assign_form"] = IncidentAssignForm(initial={"assigned_to": incident.assigned_to})
        if can_update_status:
            context["status_form"] = IncidentStatusUpdateForm(incident=incident)
        return context

class IncidentCreateView(LoginRequiredMixin, CreateView):
    model = Incident
    form_class = IncidentForm
    template_name = "incidents/form.html"

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        response = super().form_valid(form)
        messages.success(self.request, "Your incident has been recorded.")
        return response

    def get_success_url(self):
        return reverse("incidents:detail", kwargs={"pk": self.object.pk})

class IncidentAssignView(LoginRequiredMixin, View):
    """Assign or reassign an analyst to an incident. Admin-only function."""
    def post(self, request, pk):
        incident = get_object_or_404(Incident, pk=pk)
        if not can_assign_analyst(request.user, incident):
            raise PermissionDenied("Only administrators can assign analysts.")
        form = IncidentAssignForm(request.POST)
        if form.is_valid():
            incident.assigned_to = form.cleaned_data["assigned_to"]
            incident.save(update_fields=["assigned_to"])
            messages.success(request, f"Assigned analyst updated for {incident.reference}.")
        else:
            messages.error(request, "Failed to update assignment.")
        return redirect("incidents:detail", pk=incident.pk)

class IncidentStatusUpdateView(LoginRequiredMixin, View):
    """Update incident status. Assigned analyst or admin function."""
    def post(self, request, pk):
        # Must be in user's visible scope first
        incident = get_object_or_404(get_visible_incidents_for_user(request.user), pk=pk)
        if not can_update_incident_status(request.user, incident):
            raise PermissionDenied("You are not authorized to update this incident's status.")
        form = IncidentStatusUpdateForm(request.POST, incident=incident)
        if form.is_valid():
            new_status = form.cleaned_data["status"]
            try:
                incident.transition_to(new_status)
                messages.success(request, f"Status updated to {incident.get_status_display()}.")
            except Exception as e:
                messages.error(request, f"State transition rejected: {e}")
        else:
            for error in form.errors.values():
                messages.error(request, error.as_text())
        return redirect("incidents:detail", pk=incident.pk)
