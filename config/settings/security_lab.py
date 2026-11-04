"""Deliberately vulnerable, local-only synthetic SQLi exercise. Never deploy."""
import os
from django.core.exceptions import ImproperlyConfigured
from .local import *

if os.getenv("VERCEL") or os.getenv("VERCEL_ENV"):
    raise ImproperlyConfigured("The insecure security_lab settings must never run on Vercel.")
DEBUG = False
TRAINING_MODE = True
ROOT_URLCONF = "training.urls"
INSTALLED_APPS = [*INSTALLED_APPS, "training"]
# Never read DATABASE_URL here: this is a separate disposable SQLite fixture.
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "training.sqlite3"}}
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]", "app"]  # app is the private Compose service.
