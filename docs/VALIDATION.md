# Validation — 2026-10-25

## Completed

- Installed the exact Django 5.2.18 runtime dependency snapshot in a dedicated virtual environment.
- Applied all Django and incident migrations to the course's local PostgreSQL container.
- **23 tests passed** using isolated SQLite on macOS Python 3.13.2.
- **23 tests passed** using PostgreSQL on macOS Python 3.13.2.
- **23 tests passed** using PostgreSQL in Linux Python 3.12, including the platform-specific psycopg dependency resolution.
- Verified anonymous access denial, owner-only list/detail, forged-owner input, validation limits, escaped script-shaped text, SQL-shaped input as data, missing/invalid-origin CSRF rejection, private-page headers, administrator access denial for normal users, local seeder restrictions, login/session rotation and POST/CSRF logout invalidation.
- Production-settings tests verify required private configuration, PostgreSQL-only storage, secure cookies, explicit hosts and HTTPS origins.
- `makemigrations --check --dry-run` found no missing model migrations.
- `collectstatic` successfully collected the application stylesheet and Django admin assets.
- Production `check --deploy` completed with **two intentionally retained warnings**: security.W005 (no includeSubDomains) and security.W021 (no preload). These reflect a cautious short initial HSTS rollout; no other checks were silenced.
- Browser verified login, private register, creation/detail of a synthetic incident and logout. Saved actual screenshots in docs/images. Local preview used port 8765 because another service occupied 8000.
- Compose/CI YAML, Python syntax and local documentation/image links checked.

The local database uses port 55432; an existing service occupied the originally considered 5433. No unrelated service was stopped. PostgreSQL image is pinned to its tested multi-platform digest.

## Not yet verified externally

- No remote GitHub repository was created, code pushed, or GitHub Actions run triggered. The workflow is supplied and its commands were exercised locally; remote-run success is not claimed.
- No Vercel account/project or hosted PostgreSQL database was created. Native Django entrypoint/static configuration follows official documentation, but a successful Vercel deployment is not claimed until the owner configures their accounts/environment and tests it.
- No SAST/SCA/secrets/DAST pipeline is completed: these are explicit student milestones. Runtime package pins are not evidence of absence of known vulnerabilities.
- Windows setup and browser mobile layouts need classroom verification.

## Distribution

Use scripts/package_starter.py to create a clean ZIP without local .env, .venv, databases, caches or generated staticfiles. The included screenshots show synthetic local records; no real credentials or personal incident information.

## Added local SQL injection challenge

The synthetic baseline reproduced normal owner-only search, quote-triggered SQL error and injected disclosure of Bob's record as Alice. The explicit hardening suite failed in the two intended places. A temporary source copy with the owner-scoped ORM fix passed all five hardening tests; the distributed exercise remains deliberately vulnerable. The normal suite now reports 30 discovered tests: 25 pass and five opt-in challenge tests skip outside security_lab settings. Production/default URL isolation and refusal of insecure settings on Vercel are covered. No authenticated ZAP active scan has been run; scanner detection depends on scope, authentication and installed rules. The student ZIP omits the instructor's exact solution guide and every SQLite fixture file.
