# Six-week capstone milestones

The supplied version is a safe, small foundation. Add behavior with tests instead of deleting existing protections to reproduce vulnerabilities on a public site. Keep exploitable variants in disposable local labs.

| Week | Student implementation | Required evidence |
|---|---|---|
| 1 | Personal GitHub repository; local setup; first Vercel deployment; trace one change from commit to page | Architecture/DFD, initial threat model, passing baseline tests, deployed commit |
| 2 | Severity and status fields, explicit form fields, choices and migrations | Validation/negative tests, reviewed migration, allowed state transitions |
| 3 | Analyst assignment and server-side role policy | Reporter/analyst/admin access matrix; other-owner/unassigned/function denial tests |
| 4 | Plain-text comments and application audit events; review login backoff | Stored-XSS-shaped text stays inert, CSRF/session evidence, no secrets in logs |
| 5 | SAST, dependency audit, secret scan, isolated authenticated DAST | Real finding/triage/fix, regression test, scoped scan report and SBOM |
| 6 | Release policy, deployment verification, operations/report | Failing candidate withheld, passing release, rollback exercise, revised threat model |

For five weeks combine the final verification/report week with week 5 and omit custom account-management screens or other extensions. Budget independent work outside the weekly two-hour class; this is not six small classroom-only labs.

## Student decisions

- Existing baseline: reporters own their incidents. A Django superuser can administer records through a separately protected admin site.
- Expanded roles: specify reporter, assigned analyst and application administrator capabilities. Do not equate ordinary business administrators automatically with Django superusers.
- Use Django Groups/permissions and explicit object scoping where appropriate. Django's ordinary model permissions alone do not implement your custom per-incident assignment policy.
- Prevent mass assignment of owner/role/status fields through broad ModelForm fields.
- Keep CSRF middleware, ORM binding and template escaping; add negative tests demonstrating their intended use.

## Pipeline extension

The existing workflow runs behavioral tests on SQLite and PostgreSQL. Students add SAST (Semgrep or a justified equivalent), dependency and secret scanning, then a DAST job that starts a temporary app/database, creates synthetic scan identities, waits for readiness and scopes ZAP to that app. Verify it reaches authenticated pages, not just the login form. Do not actively scan arbitrary public targets or production data.

Require a real security finding or regression to fail; fix its root cause without disabling the check. Use branch/release controls available to your accounts and document the true production gate. Automatic Vercel deployment may precede a completed Actions run.

## Report and demonstration

Submit source, pipeline configuration/run links, actual deployment URL, security tests and a report covering architecture, access policy, threat model, implementation, finding triage, release enforcement, configuration/secrets, rollback and residual risks. Label framework/platform protections separately from student changes and tested evidence. A clean scanner report does not certify security.
