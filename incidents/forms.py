from django import forms
from .models import Incident

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
        # Default to MEDIUM if not specified in POST or form initialization
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
