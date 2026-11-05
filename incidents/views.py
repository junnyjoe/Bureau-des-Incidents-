import csv
import json
import re
from datetime import datetime

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.http import FileResponse, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import CreateView, DetailView, ListView, TemplateView

from .audit import record_audit_event
from .forms import (
    AttachmentUploadForm,
    CommentForm,
    IncidentAssignForm,
    IncidentForm,
    IncidentStatusUpdateForm,
)
from .models import AuditEvent, Incident, IncidentAttachment
from .permissions import (
    can_assign_analyst,
    can_update_incident_status,
    get_visible_incidents_for_user,
    is_administrator,
    is_analyst,
)
from .security_upload import validate_and_process_upload


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
    """
    Role-scoped incident register with hardened, parameterized search and filtering.
    - Full-text search across Title and Description.
    - Exact reference lookup (e.g., INC-0001).
    - Multi-criteria filtering by Status and Severity.
    - Zero vulnerability to SQL injection or BOLA/IDOR.
    """
    model = Incident
    template_name = "incidents/list.html"
    context_object_name = "incidents"
    paginate_by = 10

    def get_queryset(self):
        qs = super().get_queryset()

        # 1. Parameterized keyword / reference search
        q = self.request.GET.get("q", "").strip()
        if q:
            ref_match = re.match(r"^INC-(\d+)$", q, re.IGNORECASE)
            if ref_match:
                qs = qs.filter(pk=int(ref_match.group(1)))
            elif q.isdigit():
                qs = qs.filter(Q(pk=int(q)) | Q(title__icontains=q) | Q(description__icontains=q))
            else:
                qs = qs.filter(Q(title__icontains=q) | Q(description__icontains=q))

        # 2. Severity filter
        severity = self.request.GET.get("severity", "").strip().lower()
        if severity in Incident.Severity.values:
            qs = qs.filter(severity=severity)

        # 3. Status filter
        status = self.request.GET.get("status", "").strip().lower()
        if status in Incident.Status.values:
            qs = qs.filter(status=status)

        # 4. Date range filter
        date_from = self.request.GET.get("date_from", "").strip()
        if date_from:
            try:
                d_from = datetime.strptime(date_from, "%Y-%m-%d").date()
                qs = qs.filter(created_at__date__gte=d_from)
            except ValueError:
                pass

        date_to = self.request.GET.get("date_to", "").strip()
        if date_to:
            try:
                d_to = datetime.strptime(date_to, "%Y-%m-%d").date()
                qs = qs.filter(created_at__date__lte=d_to)
            except ValueError:
                pass

        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["is_admin"] = is_administrator(self.request.user)
        context["is_analyst"] = is_analyst(self.request.user)

        # Filter parameters to preserve in UI and pagination
        context["search_q"] = self.request.GET.get("q", "")
        context["filter_severity"] = self.request.GET.get("severity", "")
        context["filter_status"] = self.request.GET.get("status", "")
        context["filter_date_from"] = self.request.GET.get("date_from", "")
        context["filter_date_to"] = self.request.GET.get("date_to", "")
        context["severity_choices"] = Incident.Severity.choices
        context["status_choices"] = Incident.Status.choices

        params = self.request.GET.copy()
        params.pop("page", None)
        context["querystring"] = params.urlencode()
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
        context["comment_form"] = CommentForm()
        context["comments"] = incident.comments.select_related("author").all()
        context["attachment_form"] = AttachmentUploadForm()
        context["attachments"] = incident.attachments.select_related("uploaded_by").all()

        # Audit events are visible to administrators and assigned analysts
        if is_administrator(user) or (is_analyst(user) and incident.assigned_to_id == user.pk):
            context["audit_events"] = incident.audit_events.all()[:20]

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
        record_audit_event(
            action=AuditEvent.Action.INCIDENT_CREATED,
            request=self.request,
            incident=self.object,
            details=f"Created incident with title: {self.object.title}",
        )
        messages.success(self.request, "Your incident has been recorded.")
        return response

    def get_success_url(self):
        return reverse("incidents:detail", kwargs={"pk": self.object.pk})


class IncidentCommentCreateView(LoginRequiredMixin, View):
    """Add a plain-text comment to an incident in the user's authorized scope."""
    def post(self, request, pk):
        incident = get_object_or_404(get_visible_incidents_for_user(request.user), pk=pk)
        form = CommentForm(request.POST)
        if form.is_valid():
            comment = form.save(commit=False)
            comment.incident = incident
            comment.author = request.user
            comment.save()
            record_audit_event(
                action=AuditEvent.Action.COMMENT_ADDED,
                request=request,
                incident=incident,
                details=f"Comment added by {request.user.username} (length {len(comment.body)})",
            )
            messages.success(request, "Comment added.")
        else:
            for error in form.errors.values():
                messages.error(request, error.as_text())
        return redirect("incidents:detail", pk=incident.pk)


class IncidentAssignView(LoginRequiredMixin, View):
    """Assign or reassign an analyst to an incident. Admin-only function."""
    def post(self, request, pk):
        incident = get_object_or_404(Incident, pk=pk)
        if not can_assign_analyst(request.user, incident):
            raise PermissionDenied("Only administrators can assign analysts.")
        form = IncidentAssignForm(request.POST)
        if form.is_valid():
            new_assignee = form.cleaned_data["assigned_to"]
            previous_name = incident.assigned_to.username if incident.assigned_to else "Unassigned"
            new_name = new_assignee.username if new_assignee else "Unassigned"
            incident.assigned_to = new_assignee
            incident.save(update_fields=["assigned_to"])
            record_audit_event(
                action=AuditEvent.Action.ASSIGNMENT,
                request=request,
                incident=incident,
                details=f"Reassigned from {previous_name} to {new_name}",
            )
            messages.success(request, f"Assigned analyst updated for {incident.reference}.")
        else:
            messages.error(request, "Failed to update assignment.")
        return redirect("incidents:detail", pk=incident.pk)


class IncidentStatusUpdateView(LoginRequiredMixin, View):
    """Update incident status. Assigned analyst or admin function."""
    def post(self, request, pk):
        incident = get_object_or_404(get_visible_incidents_for_user(request.user), pk=pk)
        if not can_update_incident_status(request.user, incident):
            raise PermissionDenied("You are not authorized to update this incident's status.")
        form = IncidentStatusUpdateForm(request.POST, incident=incident)
        if form.is_valid():
            old_status = incident.status
            new_status = form.cleaned_data["status"]
            try:
                incident.transition_to(new_status)
                record_audit_event(
                    action=AuditEvent.Action.STATUS_CHANGE,
                    request=request,
                    incident=incident,
                    details=f"Transitioned from {old_status} to {new_status}",
                )
                messages.success(request, f"Status updated to {incident.get_status_display()}.")
            except Exception as e:
                messages.error(request, f"State transition rejected: {e}")
        else:
            for error in form.errors.values():
                messages.error(request, error.as_text())
        return redirect("incidents:detail", pk=incident.pk)


class SOCDashboardView(LoginRequiredMixin, TemplateView):
    """
    Security Operations Center (SOC) incident metrics and triage overview.
    Scoped strictly by user authorization.
    """
    template_name = "incidents/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        qs = get_visible_incidents_for_user(user)

        total = qs.count()
        open_count = qs.filter(status=Incident.Status.OPEN).count()
        in_progress_count = qs.filter(status=Incident.Status.IN_PROGRESS).count()
        resolved_count = qs.filter(status=Incident.Status.RESOLVED).count()
        closed_count = qs.filter(status=Incident.Status.CLOSED).count()

        critical_count = qs.filter(severity=Incident.Severity.CRITICAL).count()
        high_count = qs.filter(severity=Incident.Severity.HIGH).count()
        medium_count = qs.filter(severity=Incident.Severity.MEDIUM).count()
        low_count = qs.filter(severity=Incident.Severity.LOW).count()

        unassigned_count = qs.filter(assigned_to__isnull=True).exclude(
            status__in=[Incident.Status.RESOLVED, Incident.Status.CLOSED]
        ).count()

        context.update({
            "is_admin": is_administrator(user),
            "is_analyst": is_analyst(user),
            "total_incidents": total,
            "open_count": open_count,
            "in_progress_count": in_progress_count,
            "resolved_count": resolved_count,
            "closed_count": closed_count,
            "active_incidents": open_count + in_progress_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "unassigned_count": unassigned_count,
            "recent_incidents": qs[:6],
        })

        if is_administrator(user) or is_analyst(user):
            context["recent_audit"] = AuditEvent.objects.all()[:8]

        return context


def sanitize_csv_cell(value):
    """
    Neutralize CSV / Formula Injection attacks (CWE-1236).
    Prepends a single apostrophe to any cell starting with =, +, -, @, \\t, or \\r.
    """
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val_str}"
    return val_str


class IncidentExportCSVView(LoginRequiredMixin, View):
    """
    Secure CSV Export with Formula Injection neutralization (anti-CSV injection).
    Scoped strictly by user authorization.
    """
    def get(self, request):
        qs = get_visible_incidents_for_user(request.user)
        response = HttpResponse(content_type="text/csv; charset=utf-8")
        timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
        response["Content-Disposition"] = f'attachment; filename="incidents_export_{timestamp}.csv"'
        response["X-Content-Type-Options"] = "nosniff"

        writer = csv.writer(response)
        writer.writerow([
            "Reference",
            "Title",
            "Description",
            "Severity",
            "Status",
            "Reported By",
            "Assigned To",
            "Created At (UTC)",
        ])

        count = 0
        for inc in qs.iterator():
            assigned = inc.assigned_to.username if inc.assigned_to else "Unassigned"
            writer.writerow([
                sanitize_csv_cell(inc.reference),
                sanitize_csv_cell(inc.title),
                sanitize_csv_cell(inc.description),
                sanitize_csv_cell(inc.get_severity_display()),
                sanitize_csv_cell(inc.get_status_display()),
                sanitize_csv_cell(inc.created_by.username),
                sanitize_csv_cell(assigned),
                sanitize_csv_cell(inc.created_at.strftime("%Y-%m-%d %H:%M:%S")),
            ])
            count += 1

        record_audit_event(
            action=AuditEvent.Action.DATA_EXPORTED,
            request=request,
            details=f"Exported {count} incidents to CSV format (anti-formula injection applied)",
        )
        return response


class IncidentExportJSONView(LoginRequiredMixin, View):
    """
    Structured JSON audit export scoped strictly by authorization.
    """
    def get(self, request):
        qs = get_visible_incidents_for_user(request.user)
        data = []
        for inc in qs:
            data.append({
                "reference": inc.reference,
                "title": inc.title,
                "description": inc.description,
                "severity": inc.severity,
                "status": inc.status,
                "created_by": inc.created_by.username,
                "assigned_to": inc.assigned_to.username if inc.assigned_to else None,
                "created_at": inc.created_at.isoformat(),
            })

        record_audit_event(
            action=AuditEvent.Action.DATA_EXPORTED,
            request=request,
            details=f"Exported {len(data)} incidents to JSON format",
        )
        response = JsonResponse(data, safe=False, json_dumps_params={"indent": 2})
        timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
        response["Content-Disposition"] = f'attachment; filename="incidents_export_{timestamp}.json"'
        response["X-Content-Type-Options"] = "nosniff"
        return response


class IncidentAttachmentUploadView(LoginRequiredMixin, View):
    """
    Upload forensic evidence or operational attachments.
    Enforces magic bytes verification, file size quotas, path traversal defense, and SHA-256 integrity.
    """
    def post(self, request, pk):
        incident = get_object_or_404(get_visible_incidents_for_user(request.user), pk=pk)
        form = AttachmentUploadForm(request.POST, request.FILES)

        if form.is_valid():
            uploaded_file = form.cleaned_data["file"]
            try:
                content_type, sha256_hash = validate_and_process_upload(uploaded_file)
                attachment = IncidentAttachment.objects.create(
                    incident=incident,
                    uploaded_by=request.user,
                    original_filename=uploaded_file.name[:255],
                    file=uploaded_file,
                    content_type=content_type,
                    file_size=uploaded_file.size,
                    sha256_hash=sha256_hash,
                )
                record_audit_event(
                    action=AuditEvent.Action.ATTACHMENT_UPLOADED,
                    request=request,
                    incident=incident,
                    details=f"Attached '{attachment.original_filename}' ({attachment.file_size} bytes, SHA-256: {sha256_hash[:16]}...)",
                )
                messages.success(request, f"Evidence file '{attachment.original_filename}' uploaded successfully.")
            except ValidationError as err:
                messages.error(request, f"Upload rejected: {err.message if hasattr(err, 'message') else str(err)}")
            except Exception as err:
                messages.error(request, f"Upload error: {str(err)}")
        else:
            for error in form.errors.values():
                messages.error(request, error.as_text())

        return redirect("incidents:detail", pk=incident.pk)


class IncidentAttachmentDownloadView(LoginRequiredMixin, View):
    """
    Secure file streaming for incident attachments.
    Scoped by incident permissions; returns 404 for unauthorized users.
    Disables code execution via nosniff and attachment disposition.
    """
    def get(self, request, attachment_id):
        attachment = get_object_or_404(IncidentAttachment, pk=attachment_id)
        # Verify access to parent incident
        get_object_or_404(get_visible_incidents_for_user(request.user), pk=attachment.incident_id)

        record_audit_event(
            action=AuditEvent.Action.ATTACHMENT_DOWNLOADED,
            request=request,
            incident=attachment.incident,
            details=f"Downloaded attachment '{attachment.original_filename}' (ID: {attachment.pk})",
        )

        response = FileResponse(attachment.file.open("rb"), as_attachment=True, filename=attachment.original_filename)
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, no-store"
        return response
