"""Remediated incident search using the Django ORM."""
from django.db import connection
from incidents.models import Incident

def search_incidents(user_id, query):
    if connection.vendor != "sqlite":
        raise RuntimeError("The insecure exercise requires its isolated SQLite database.")
    return list(
        Incident.objects.filter(created_by_id=user_id, title__contains=query)
        .order_by("-created_at")
        .values("id", "title", "description")[:20]
    )
