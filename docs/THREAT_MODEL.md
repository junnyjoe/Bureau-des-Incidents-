# Threat Model & STRIDE Analysis (Revised v2)

## 1. System Boundary and Data Flow

```text
[ Browser / Client ] 
        │  (HTTPS, TLS 1.3, CSP, CSRF Tokens, Secure HttpOnly Cookies)
        ▼
[ Application Gateway / Vercel ]
        │  (Reverse proxy, Environment configuration: DJANGO_SECRET_KEY, DATABASE_URL)
        ▼
[ Django 5 Application (Incident Desk) ]
   ├── Authentication & Session Management (Django Auth, Session rotation on login, POST+CSRF logout)
   ├── Authorization & Scope Layer (get_visible_incidents_for_user: Reporter / Analyst / Admin)
   ├── Input Validation & Sanitization (forms.ModelForm explicit field allowlists, state transition machine)
   ├── Anti-XSS Engine (Django template autoescaping, plain-text comment rendering)
   └── Audit Logging Subsystem (AuditEvent model + structured logger, credentials stripped)
        │  (Parameterized ORM queries, TLS connection)
        ▼
[ Managed Database / PostgreSQL / Neon ]
```

---

## 2. Assets and Core Controls

| Asset | Criticality | Implemented Controls | Verification Evidence |
|---|---|---|---|
| **Incident Content & Confidentiality** | High | Owner and assignment-scoped ORM queries (`get_visible_incidents_for_user`), 404 on unpermitted lookup | `test_roles.py`, `test_incidents.py` |
| **Authentication & Sessions** | High | PBKDF2/argon2 password hashing, session rotation on login, CSRF tokens on state-changing requests, POST-only logout | `test_incidents.py` (SessionTests) |
| **Operational State Integrity** | Medium | Finite-state machine `ALLOWED_TRANSITIONS`, `IncidentStatusUpdateForm`, validation on `clean()` | `IncidentLifecycleAndValidationTests` |
| **Comments & Output Integrity** | Medium | Plain-text restriction, Django auto-escaping in templates, Content Security Policy | `test_audit_and_xss.py` (anti-XSS suite) |
| **Audit Logs & Traceability** | High | Immutable `AuditEvent` log, IP/username capture, strict redaction of credentials/tokens | `test_audit_and_xss.py` |
| **Secrets & Keys** | Critical | Loaded via environment variables only; `.env` excluded in `.gitignore`; secret scan via TruffleHog | GitHub Actions `secret-scan` job |

---

## 3. Prioritized STRIDE Threat Analysis

Scoring model based on DREAD/OWASP (Likelihood: Low/Med/High, Impact: Low/Med/High).

| ID | STRIDE Category | Threat Scenario & Target Asset | Likelihood | Impact | Implemented Control | Test & Verification | Status |
|:---:|:---:|---|:---:|:---:|---|---|:---:|
| **T1** | **Information Disclosure** | **SQL Injection in Search**<br>Attacker injects boolean payload (`%' OR 1=1 -- `) into incident search to disclose cross-tenant incidents. | High | High | Replaced raw string concatenation with Django ORM parameterized lookup (`Incident.objects.filter(...)`). | `training.tests.test_hardening` (5/5 PASS) | **Mitigated** |
| **T2** | **Elevation of Privilege** | **Mass Assignment in Creation Form**<br>Reporter attempts to forge `status="resolved"` or `created_by` in POST payload during creation. | High | High | Explicit allowlist in `IncidentForm.Meta.fields = ["title", "description", "severity"]`; server-side binding. | `test_mass_assignment_status_ignored_on_creation` | **Mitigated** |
| **T3** | **Information Disclosure (BOLA)** | **Cross-Analyst / Cross-Reporter Access**<br>An analyst attempts to view an unassigned incident or one assigned to another analyst via direct URL probing. | Med | High | Server-side role scoping via `get_visible_incidents_for_user`; returns 404 rather than disclosing existence. | `test_roles.py` (12/12 PASS) | **Mitigated** |
| **T4** | **Tampering (Stored XSS)** | **Malicious Script Injection in Comments**<br>Attacker injects `<script>` or `<img onerror=...>` in incident comments to execute JavaScript in analyst's browser. | Med | High | Plain-text textarea, strict Django HTML autoescaping in templates, no `|safe` filter, CSP `script-src 'self'`. | `test_comment_stored_xss_payload_stays_inert` | **Mitigated** |
| **T5** | **Repudiation** | **Untracked Sensitive Actions**<br>Analyst or admin alters status or reassigns incident without forensic accountability. | Med | Med | Centralized `record_audit_event()` logging actor, event type, IP address, and timestamp; password redaction. | `test_audit_event_recorded_on_assignment_and_status` | **Mitigated** |
| **T6** | **Information Disclosure** | **Credential / Secret Leakage in Source or Logs**<br>Developers commit `.env` or write plaintext passwords/tokens to log files. | Med | Critical | `.env` ignored by Git; Semgrep SAST rule; TruffleHog CI scan; `audit.py` sanitizer stripping secrets. | `test_no_secrets_in_audit_records`, Semgrep (0 findings) | **Mitigated** |
| **T7** | **Denial of Service / Spoofing** | **Credential Stuffing & Login Brute Force**<br>Attacker executes automated dictionary attack against `/accounts/login/`. | High | High | Server-side IP rate-limiter with 5-attempt threshold, 5-minute lockout (HTTP 429), and security audit logging. | `incidents.tests.test_ratelimit` (6/6 PASS) | **Mitigated** |
| **T8** | **Elevation of Privilege** | **Session Hijacking via Abandoned Terminals**<br>Analyst leaves workstation unattended, allowing unauthorized physical session reuse. | Med | High | Sliding Session Idle Timeout (`SessionIdleTimeoutMiddleware`): 15min for privileged roles, 30min standard, automatic logout and audit trail. | `incidents.tests.test_idle_timeout` (4/4 PASS) | **Mitigated** |
| **T9** | **Spoofing / Elevation of Privilege** | **Privileged Account Takeover via Stolen Passwords**<br>Attacker obtains analyst or administrator password via phishing or leak. | High | Critical | Mandatory Time-based One-Time Password (TOTP, RFC 6238) Two-Factor Authentication enforced on Analyst and Administrator logins. | `incidents.tests.test_two_factor` (10/10 PASS) | **Mitigated** |
| **T10** | **Spoofing** | **Weak & Easily Guessable Credentials**<br>Users set simplistic passwords vulnerable to offline cracking or credential guessing. | Med | High | Enterprise `ComplexityPasswordValidator` enforcing minimum length (12+), uppercase, lowercase, numbers, and special symbols. | `incidents.tests.test_password_complexity` (6/6 PASS) | **Mitigated** |
| **T11** | **Tampering / Code Execution** | **CSV / Formula Injection (CWE-1236)**<br>Attacker injects formula triggers (`=`, `@`, `+`, `-`) in incident title/description to execute commands in spreadsheet viewers. | High | High | Strict cell prefix neutralization (`sanitize_csv_cell`) escaping formula triggers with a single quote. | `incidents.tests.test_export` (3/3 PASS) | **Mitigated** |
| **T12** | **Tampering / RCE** | **Malicious File Upload & Web Shell Execution**<br>Attacker uploads executable script or polyglot disguised as an image/log file. | High | Critical | Magic byte inspection (`validate_and_process_upload`), extension denylist, UUID4 filename obfuscation, nosniff headers, and SHA-256 integrity. | `incidents.tests.test_attachments` (5/5 PASS) | **Mitigated** |

---

## 4. Residual Risks and Accepted Trade-offs

1. **Hardware Security Keys (WebAuthn / FIDO2)**:
   - *Current state*: Two-Factor Authentication is fully enforced using RFC 6238 TOTP (authenticator apps). Hardware FIDO2/U2F security keys (YubiKey) are planned for enterprise scale.
2. **Infrastructure DDoS**:
   - *Current state*: Application-layer brute-force, request flooding, and credential stuffing are blocked at the application level; volumetric L3/L4 DDoS attacks are absorbed upstream by Vercel Edge proxies and Anycast network.


