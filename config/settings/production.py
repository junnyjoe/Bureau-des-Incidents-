import os
import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from .base import *

def required(name):
    value = os.getenv(name, "").strip()
    if not value:
        raise ImproperlyConfigured(f"Set {name} in the deployment environment.")
    return value

def csv(name):
    values = [value.strip() for value in required(name).split(",") if value.strip()]
    if not values:
        raise ImproperlyConfigured(f"Set at least one entry in {name}.")
    return values

if os.getenv("INCIDENT_DESK_INSECURE_LAB"):
    raise ImproperlyConfigured("Deliberately insecure lab mode is forbidden in production.")
TRAINING_MODE = False
DEBUG = False
SECRET_KEY = required("DJANGO_SECRET_KEY")
if len(SECRET_KEY) < 50 or SECRET_KEY.startswith("django-insecure-"):
    raise ImproperlyConfigured("Use a random production DJANGO_SECRET_KEY of at least 50 characters.")
ALLOWED_HOSTS = csv("DJANGO_ALLOWED_HOSTS")
if any("*" in host for host in ALLOWED_HOSTS):
    raise ImproperlyConfigured("Use explicit hostnames, not wildcard allowed hosts.")
CSRF_TRUSTED_ORIGINS = csv("DJANGO_CSRF_TRUSTED_ORIGINS")
if any(not origin.startswith("https://") or "*" in origin for origin in CSRF_TRUSTED_ORIGINS):
    raise ImproperlyConfigured("Use explicit HTTPS CSRF trusted origins.")
url = required("DATABASE_URL")
if not url.startswith(("postgres://", "postgresql://")):
    raise ImproperlyConfigured("Production requires PostgreSQL, not a local database file.")
DATABASES = {"default": dj_database_url.parse(url, conn_max_age=0, ssl_require=True)}
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
# Only deploy these settings behind a trusted proxy that sets/overwrites this header.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_HSTS_SECONDS = 300  # Deliberately short initial rollout policy.
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
