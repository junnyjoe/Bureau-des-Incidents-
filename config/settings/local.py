import os
import secrets
import dj_database_url
from .base import *

DEBUG = True
# A temporary local key is acceptable; set a stable private key in .env to preserve local sessions.
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY") or secrets.token_urlsafe(50)
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]
DATABASES = {"default": dj_database_url.parse(
    os.getenv("DATABASE_URL", "postgresql://incidentdesk:local-course-only@127.0.0.1:55432/incidentdesk"),
    conn_max_age=0,
)}
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
