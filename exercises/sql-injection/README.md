# Security challenge — Find and fix incident-search SQL injection

## Goal

Use ZAP/manual requests to identify an unsafe database query in an added search feature. Fix the underlying query while retaining owner-based access and normal search behavior. This challenge is separate from the safe Version 0 workflow.

## Start only the isolated local exercise

From the project folder, with your Python environment active:

```bash
python manage.py migrate --settings=config.settings.security_lab
python manage.py seed_security_lab --settings=config.settings.security_lab
python manage.py runserver 127.0.0.1:8001 --insecure --settings=config.settings.security_lab
```

Here `--insecure` is Django's development-server switch to serve local static CSS with DEBUG=False; it does not turn off authentication or CSRF. Bind only to 127.0.0.1. The training settings ignore DATABASE_URL and use a separate disposable training.sqlite3 file. Do not use real information. Never deploy these settings or run this challenge on Vercel.

Log in at http://127.0.0.1:8001/accounts/login/ as **lab-alice**, password **local-training-only**. The other synthetic account is lab-bob with the same public lab password. These accounts exist only in the local exercise database.

Open http://127.0.0.1:8001/training/search/. The ordinary incident list/detail endpoints remain owner-protected; the new search endpoint is the intentionally flawed feature.

## Alternative: all-Docker app and ZAP

Use this instead of the host runserver commands when you want Dockerized ZAP:

```bash
docker compose -f compose.security-lab.yml up -d --build
docker compose -f compose.security-lab.yml logs --tail=20 app
```

Wait for app startup/migrations. Open ZAP's interface at http://localhost:8085/zap in your normal browser first. Set the separate lab browser's HTTP proxy to 127.0.0.1:8095. In that proxied browser open **http://app:8001/accounts/login/**, sign in as lab-alice, then open **http://app:8001/training/search/**. ZAP resolves `app` on the private Docker network; that hostname is not expected to resolve in a non-proxied browser. Do not use the host's 127.0.0.1 address as the target inside ZAP.

Only app/ZAP ports are loopback-published; the runtime training network has no external egress. The database exists in the exercise app container, never your hosted database. To load a student's saved source fix rebuild the app (`docker compose -f compose.security-lab.yml up -d --build app`), then log in again. No live source mount exists. Run the gate with:

```bash
docker compose -f compose.security-lab.yml exec app python manage.py test training.tests.test_hardening --settings=config.settings.security_lab
```

Stop/reset this disposable environment using `docker compose -f compose.security-lab.yml down`. Pin a tested ZAP image digest before distributing a frozen cohort release. Docker setup requires image download/build before class.

## Discover and reproduce

1. With **desktop ZAP**, use a dedicated proxy browser profile or launch a browser from ZAP. For **Dockerized ZAP**, use the separate Compose option below; container localhost is not your host machine. Confirm the authenticated search request and response appear in History.
2. Search `laptop`: expect Alice's synthetic result and no Bob result.
3. Search a single quote `'`: record the returned training database error. An error alone is a lead, not the complete proof.
4. Try the controlled boolean probe in the form:

```text
%' OR 1=1 -- 
```

5. Record Bob's **BOB_PRIVATE_FIXTURE** in Alice's response. Do not enumerate unrelated files/tables or retrieve password/session data. The lookup is read-only and limits fetched rows, but those containment measures do not prevent disclosure.
6. Explain the constructed WHERE expression: which quote closed the title value, which condition became true, and which trailing text was commented out?

## Using ZAP as a scanner

A passive/baseline scan does not send SQL-injection attacks. For an active test, put only the local `/training/search/` path in scope, seed a real request with `q=laptop`, and enable the SQL Injection scan rule. Avoid broad scans of login, admin, logout and other state-changing functionality.

Configure/reuse the lab-alice session and verify that scans receive the search response rather than a redirect to login. Browser proxying alone does not guarantee that an automated active scan uses the authenticated identity. Record ZAP version, installed rules, scope, authentication setup, payload/evidence and finding confidence. ZAP may produce an SQLi alert depending on rule/configuration; a missing alert is not proof of safety. Preserve the manual reproduction as deterministic evidence.

Sources: https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/ and https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/

## Remediate

Inspect training/search.py. Replace query concatenation with an owner-scoped ORM query (or a correctly parameterized equivalent). Keep the returned dictionaries' id/title/description fields and a bounded result count. Do not remove authentication, the search route, the ownership policy or legitimate results. Hiding an error or filtering a quote alone is not the required fix.

Add tests of your own. Your solution must preserve the logged-in owner restriction as well as separate query structure from data.

## Run the hardening gate

```bash
python manage.py test training.tests.test_hardening --settings=config.settings.security_lab
```

**Before the fix:** two tests fail: injected cross-owner disclosure and quote-triggered database errors. Three positive/control tests pass. **After a correct fix:** all five pass. The test runner uses a disposable test database, not your saved training.sqlite3 records.

Running only the ordinary starter test suite is not sufficient: these challenge tests are skipped outside the training settings. When adding CI for this challenge, explicitly run the command above. Keep the instructor's authoritative copy of the tests separate from student submissions.

Repeat your manual payload and normal searches in ZAP after the fix, using the same identity, endpoint and scope. Document actual outcomes and any remaining scanner findings. A clean scan alone does not establish remediation.

## Evidence to submit

- ZAP/request evidence of the original cross-owner disclosure.
- Root cause and confidentiality impact.
- Code diff showing fixed query construction and retained owner scope.
- The original failing test run and corrected five-test passing run.
- Before/after replay plus a successful normal search.
- Confirmation the deployed normal application does not expose `/training/search/`.

## Deployment and cleanup

The normal URL configuration excludes the challenge. Production settings always set TRAINING_MODE=False, and the insecure settings refuse Vercel environment markers. Do not rely on these alone to justify publishing vulnerable source as an active service. Remove the exercise feature, or incorporate only its repaired search into ordinary owner-protected application routes when extending your capstone.

Stop the local server when finished. Preserve the initial evidence and your fix. The SQLite file contains only synthetic exercise data and is excluded from Git and the distribution ZIP. Use the original starter to repeat the vulnerable state instead of weakening the deployed application.
