import os
import secrets
import subprocess
import sys
from django.test import SimpleTestCase

class ProductionConfigurationTests(SimpleTestCase):
    def run_settings(self, **changes):
        env = {key: value for key, value in os.environ.items() if not key.startswith(('DJANGO_', 'DATABASE_URL'))}
        env.update({
            'DJANGO_SETTINGS_MODULE': 'config.settings.production',
            'DJANGO_SECRET_KEY': secrets.token_urlsafe(50),
            'DATABASE_URL': 'postgresql://test:test@localhost/course',
            'DJANGO_ALLOWED_HOSTS': 'incident.example.invalid',
            'DJANGO_CSRF_TRUSTED_ORIGINS': 'https://incident.example.invalid',
        })
        for key, value in changes.items():
            if value is None: env.pop(key, None)
            else: env[key] = value
        return subprocess.run([sys.executable, '-c', 'from django.conf import settings; print(settings.DEBUG, settings.SESSION_COOKIE_SECURE, settings.CSRF_COOKIE_SECURE, settings.DATABASES["default"]["ENGINE"])'], env=env, capture_output=True, text=True)

    def test_production_is_secure_and_uses_postgres(self):
        result = self.run_settings()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('False True True django.db.backends.postgresql', result.stdout)

    def test_missing_secret_is_rejected(self):
        self.assertNotEqual(self.run_settings(DJANGO_SECRET_KEY=None).returncode, 0)

    def test_sqlite_is_rejected_in_production(self):
        self.assertNotEqual(self.run_settings(DATABASE_URL='sqlite:///db.sqlite3').returncode, 0)

    def test_wildcard_host_and_non_https_trusted_origin_are_rejected(self):
        self.assertNotEqual(self.run_settings(DJANGO_ALLOWED_HOSTS='*').returncode, 0)
        self.assertNotEqual(self.run_settings(DJANGO_CSRF_TRUSTED_ORIGINS='http://example.invalid').returncode, 0)


class TrainingIsolationTests(SimpleTestCase):
    def test_default_urlconf_does_not_expose_training_search(self):
        from django.test import Client
        self.assertEqual(Client().get('/training/search/').status_code, 404)

    def test_training_settings_refuse_vercel(self):
        env = os.environ.copy()
        env['VERCEL'] = '1'
        result = subprocess.run([sys.executable, '-c', 'import config.settings.security_lab'], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must never run on Vercel', result.stderr)
