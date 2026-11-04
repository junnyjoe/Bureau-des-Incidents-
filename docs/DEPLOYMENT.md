# Deploy Incident Desk to Vercel Hobby

## Before you start

Publish this folder as the root of your personal GitHub repository. Choose the Hobby plan, without enabling a paid trial for the exercise. Use synthetic data. Vercel hosts the Django application; PostgreSQL is a separate service. Review both providers' current free limits.

Create an isolated hosted PostgreSQL database (for example Neon Free) and obtain its TLS connection URL. Prefer the provider's documented pooled application connection for serverless use; some operations may require its direct connection. Do not reuse a production database or share a database across students. No file upload storage is included.

## 1. Configure a private deployment environment

Import the personal repository into Vercel, select its root containing manage.py, and use the detected Django framework. The project declares config.wsgi:application in pyproject.toml. Native Django support collects STATIC_ROOT automatically and serves static assets; no legacy /api rewrite or Docker deployment is required.

Set environment variables explicitly:

| Variable | Value |
|---|---|
| DJANGO_SETTINGS_MODULE | config.settings.production |
| DJANGO_SECRET_KEY | A new random, private value of at least 50 characters; keep stable across releases |
| DATABASE_URL | Isolated hosted PostgreSQL URL with TLS |
| DJANGO_ALLOWED_HOSTS | Exact hostnames, comma-separated, no scheme/path/wildcards |
| DJANGO_CSRF_TRUSTED_ORIGINS | Exact https:// origins, comma-separated, no wildcard |

Generate the secret with `python -c "import secrets; print(secrets.token_urlsafe(50))"` and copy it privately to Vercel. Never commit it. Different preview and production environments should have separate secrets/databases. The local .env is not uploaded.

Production settings require these variables, refuse SQLite/wildcard hosts, use secure cookies and TLS database access. They trust X-Forwarded-Proto only behind the deployment platform's trusted proxy. Do not use this proxy trust configuration on an arbitrary directly exposed server.

If you do not know the final project hostname until the first deployment, create/import the project, obtain its assigned name, then set the exact host/origin and redeploy. An initial configuration error is preferable to allowing every hostname. Add any specific preview hostname deliberately; do not automatically trust every *.vercel.app site.

## 2. Apply the schema deliberately

Before serving real course traffic, run migrations against the intended hosted database from a trusted local shell. Use the same application revision, with the venv active. For macOS/Linux export the five variables above in that shell; PowerShell uses `$env:NAME = 'value'`. Do not paste actual secrets into shared terminals/screenshots. If terminal history is a concern, use a private, gitignored environment file and your approved environment loader instead.

After selecting production settings and the target DATABASE_URL:

```bash
python manage.py check --deploy
python manage.py migrate --plan
python manage.py migrate --noinput
python manage.py createsuperuser
```

Review the database target before applying migrations. Never run the test suite or demo seeder against it. No default production administrator exists. Django's production security checks may warn about HSTS includeSubDomains and preload: both are deliberately disabled for a cautious initial rollout. Do not silence warnings without understanding them or enable preload casually. Begin with the short 300-second HSTS policy and choose a production policy after testing.

The starter does **not** migrate during the build: preview builds must not race to change production schemas. In later milestones put migrations into a controlled release procedure, considering compatibility with old/new code and backups. Rollback of application code does not automatically reverse schema/data changes.

## 3. Deploy and smoke-test

Deploy through the connected repository. Check build logs and record the commit. Verify:

- Login page and stylesheet load with HTTPS.
- Your private administrator can create a normal course reporter.
- Reporter can create/view its own synthetic record.
- A second reporter cannot open the first record's direct URL.
- Logout works; anonymous users cannot open incident pages.
- Cookies have Secure/HttpOnly/SameSite as appropriate; CSP and other response headers appear.
- No debug traceback, key, credential or database URL is disclosed.

This project contains deployment configuration, but a local test does not establish a successful Vercel deployment. Record your actual deployment URL and evidence.

## 4. Preview and security testing

Do not point preview builds at production data. Use a separate test database/environment or restrict initial deployment to your stable main branch until isolation is configured. Vercel Git integration may deploy automatically before GitHub tests finish; a red test is not a deployment gate by itself.

For the capstone, run ZAP against a disposable local app in GitHub Actions with synthetic records. Bound scanning scope, verify authenticated coverage, triage findings, then release deliberately. Students must document and test how failing checks prevent production release using their actual available plan/settings; do not assume paid deployment checks/protection are enabled on Hobby.

## Troubleshooting

- DisallowedHost: correct the exact hostname in DJANGO_ALLOWED_HOSTS and redeploy.
- CSRF 403 on an otherwise legitimate form: inspect origin, HTTPS/proxy information and trusted origins; never disable CSRF middleware to fix it.
- Missing relation/table: verify migration target and schema; do not migrate on every request.
- Database connection failure: verify URL encoding, TLS, provider connection limits and pooled/direct guidance. Do not publish the URL in logs.
- Stylesheet missing: confirm native Django detection, STATIC_ROOT and collectstatic build logs; don't commit generated staticfiles.
- Logout 405 on a typed URL: use the POST logout button; a state-changing GET is intentionally unsupported.

Sources checked during project preparation:

- https://vercel.com/docs/frameworks/full-stack/django
- https://vercel.com/kb/guide/is-sqlite-supported-in-vercel
- https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/
- https://neon.com/pricing

The optional compose.security-lab.yml and config.settings.security_lab are deliberately vulnerable local teaching resources. They must not be used as deployment settings or services. The deployable application's normal URL configuration excludes the challenge route.
