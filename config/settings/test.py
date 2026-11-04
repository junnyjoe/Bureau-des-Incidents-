from .base import *
DEBUG = False
SECRET_KEY = "isolated-test-key-only-not-a-deployment-secret"
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
# Only the test suite uses fast hashes. Never import these settings in deployment.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
