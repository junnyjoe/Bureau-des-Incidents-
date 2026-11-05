from django import forms
from django.contrib.auth import get_user_model
from .models import Comment, Incident
from .permissions import ROLE_ADMINISTRATORS, ROLE_ANALYSTS

class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        # Ownership and status are strictly managed on the server side to prevent mass assignment.
        fields = ["title", "description", "severity"]
        widgets = {
            "title": forms.TextInput(attrs={"placeholder": "A short, descriptive title", "autofocus": True}),
            "description": forms.Textarea(attrs={"rows": 8, "placeholder": "What happened? Include synthetic details only."}),
            "severity": forms.Select(attrs={"class": "form-select"}),
        }
        help_texts = {
            "title": "3–150 characters.",
            "description": "10–5,000 characters. Use plain text; do not enter passwords or personal data.",
            "severity": "Select the estimated impact of this incident.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["severity"].required = False
        if not self.initial.get("severity"):
            self.initial["severity"] = Incident.Severity.MEDIUM

    def clean_severity(self):
        severity = self.cleaned_data.get("severity")
        if not severity:
            return Incident.Severity.MEDIUM
        if severity not in Incident.Severity.values:
            raise forms.ValidationError("Invalid severity selected.")
        return severity

class IncidentAssignForm(forms.Form):
    assigned_to = forms.ModelChoiceField(
        queryset=get_user_model().objects.none(),
        required=False,
        empty_label="-- Unassigned --",
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        User = get_user_model()
        self.fields["assigned_to"].queryset = User.objects.filter(
            groups__name__in=[ROLE_ANALYSTS, ROLE_ADMINISTRATORS]
        ).distinct()

class IncidentStatusUpdateForm(forms.Form):
    status = forms.ChoiceField(
        choices=Incident.Status.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    def __init__(self, *args, incident=None, **kwargs):
        self.incident = incident
        super().__init__(*args, **kwargs)
        if incident:
            self.fields["status"].initial = incident.status

    def clean_status(self):
        new_status = self.cleaned_data.get("status")
        if self.incident and not self.incident.can_transition_to(new_status):
            raise forms.ValidationError(
                f"Invalid transition from {self.incident.get_status_display()} to {dict(Incident.Status.choices).get(new_status, new_status)}."
            )
        return new_status

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        # Author and incident are bound server-side. Only body is accepted from user.
        fields = ["body"]
        widgets = {
            "body": forms.Textarea(attrs={
                "rows": 4,
                "placeholder": "Add a plain-text operational comment... (HTML tags will remain unexecuted)",
                "class": "form-control",
            }),
        }
        help_texts = {
            "body": "Plain text only (2–2,000 characters). Do not include credentials or personal data.",
        }


class AttachmentUploadForm(forms.Form):
    file = forms.FileField(
        label="Select evidence file",
        help_text="Max 5 MB. Allowed formats: .txt, .log, .csv, .json, .pdf, .png, .jpg, .gif, .webp",
        widget=forms.FileInput(attrs={"class": "form-control"}),
    )

