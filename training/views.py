from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db import DatabaseError
from django.http import Http404
from django.shortcuts import render
from .search import search_incidents

@login_required
def search(request):
    if not getattr(settings, "TRAINING_MODE", False):
        raise Http404
    query = request.GET.get("q", "")
    if len(query) > 200:
        return render(request, "training/search.html", {"query":query, "error":"Search must be at most 200 characters.", "results":[]}, status=400)
    error = ""
    try:
        results = search_incidents(request.user.pk, query)
    except DatabaseError as exc:
        # Deliberate error-based SQLi clue, only in this synthetic local exercise.
        results = []
        error = f"Training database error: {exc}"
    return render(request, "training/search.html", {"query":query, "results":results, "error":error})
