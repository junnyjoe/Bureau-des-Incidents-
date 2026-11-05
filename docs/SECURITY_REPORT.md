# Incident Desk — Capstone Security Engineering Report

**Project**: Application Security Capstone (Incident Desk)  
**Target Environment**: Python 3.12/3.13 · Django 5.2.18 · PostgreSQL · Vercel Deployment  
**Repository Branch**: `master`  
**Security Status**: All Gates Passing · SAST Clean · SCA Clean · Hardening Verified (61/61 Tests Passing)

---

## 1. Executive Summary

Incident Desk is a secured multi-role incident management platform designed to prevent common web vulnerabilities (OWASP Top 10) through defense-in-depth architecture. Over six progressive milestones, the application was engineered from an initial baseline into a hardened operational platform featuring:
- Strict role-based access control (RBAC) separating Reporters, Analysts, and Administrators.
- Server-side scoped queries preventing Broken Object-Level Authorization (BOLA/IDOR).
- Finite-state machine governing allowed incident state transitions.
- Protection against Mass Assignment attacks on creation and update endpoints.
- Auto-escaped plain-text operational comments neutralizing Stored Cross-Site Scripting (XSS).
- Sanitized security audit logging with zero credential leakage.
- Anti-brute force and credential-stuffing defense with IP-based rate limiting, cooldown lockouts (HTTP 429), and audit logging.
- Automated CI/CD security pipeline running behavioral tests, SAST (Semgrep), SCA (pip-audit), secret scanning (TruffleHog), and DAST (OWASP ZAP).

---

## 2. Architecture & Data Flow

```text
               ┌────────────────────────────────────────────────────────┐
               │                     Web Browser                        │
               │  - HTTPS / TLS 1.3 only                                │
               │  - Strict Content-Security-Policy                      │
               │  - HttpOnly, SameSite=Lax, Secure Session & CSRF Cookies│
               └───────────────────────────┬────────────────────────────┘
                                           │
                                    HTTPS Requests
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │                Vercel Application Gateway              │
               │  - Edge proxy & TLS termination                        │
               │  - Injected Environment Variables (.env isolation)     │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                           Django 5.2 Application Core                                 │
│                                                                                       │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────────┐  │
│  │ Security Middleware     │  │ Authentication System    │  │ Authorization Policy │  │
│  │ - CSRF Validation       │  │ - Session rotation       │  │ - Role Scoping (ORM) │  │
│  │ - Cache: no-store       │  │ - PBKDF2 Password Hash   │  │ - BOLA Prevention    │  │
│  │ - X-Frame-Options: DENY │  │ - POST-only Logout       │  │ - Action Gates (403) │  │
│  └─────────────────────────┘  └──────────────────────────┘  └──────────────────────┘  │
│                                                                                       │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────────┐  │
│  │ Input Validation        │  │ Output Encoding          │  │ Audit Logger         │  │
│  │ - Explicit Form Fields  │  │ - Template Auto-escape   │  │ - Immutable events   │  │
│  │ - State Machine Clean   │  │ - Inert Plain-text       │  │ - Secret Redaction   │  │
│  └─────────────────────────┘  └──────────────────────────┘  └──────────────────────┘  │
└──────────────────────────────────────────┬────────────────────────────────────────────┘
                                           │ Parameterized Queries / TLS
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │         Managed Database (PostgreSQL / Neon)           │
               │  - Isolated network access                             │
               │  - Explicit schema indexes on (owner, status, assigned)│
               └────────────────────────────────────────────────────────┘
```

---

## 3. Access Control & Role Matrix (RBAC)

The application enforces server-side role segregation using Django Groups and query scoping. Business roles are decoupled from Django superuser status.

| Role | Incident Visibility | Can Create | Can Update Status | Can Assign Analyst | Can Comment |
|---|---|:---:|:---:|:---:|:---:|
| **Anonymous** | None (Redirected to `/accounts/login/`) | ❌ (302) | ❌ (302) | ❌ (302) | ❌ (302) |
| **Reporter** | Only incidents created by self | ✅ (Auto-owned) | ❌ (403) | ❌ (403) | ✅ (Own incidents) |
| **Analyst** | Only assigned incidents + created by self | ✅ (Auto-owned) | ✅ (Assigned only) | ❌ (403) | ✅ (Scoped incidents) |
| **Administrator** | All incidents in the system | ✅ (Auto-owned) | ✅ (All incidents) | ✅ (All incidents) | ✅ (All incidents) |

### Object-Level Scoping Mechanism (`incidents/permissions.py`)
```python
def get_visible_incidents_for_user(user):
    if not user or not user.is_authenticated:
        return Incident.objects.none()
    if is_administrator(user):
        return Incident.objects.all()
    if is_analyst(user):
        return Incident.objects.filter(Q(assigned_to=user) | Q(created_by=user))
    return Incident.objects.filter(created_by=user)
```
Attempting to access an incident outside one's authorized scope evaluates to empty in `DetailView.get_queryset()`, deterministically raising **HTTP 404 Not Found** to prevent identifier enumeration.

---

## 4. Key Vulnerabilities & Engineering Remediations

### 4.1 SQL Injection Remediation (`training/search.py`)
- **Vulnerability**: Concaténation f-string brute dans une clause SQL SQLite :  
  `WHERE created_by_id = {int(user_id)} AND title LIKE '%{query}%'`
- **Exploitation**: Avec le payload `%' OR 1=1 -- `, la condition propriétaire était annulée, exposant les enregistrements confidentiels de tiers (`BOB_PRIVATE_FIXTURE`).
- **Remediation**: Remplacement par l'ORM Django paramétré :
```python
return list(
    Incident.objects.filter(created_by_id=user_id, title__contains=query)
    .order_by("-created_at")
    .values("id", "title", "description")[:20]
)
```
- **Résultat**: Les caractères métasyntaxiques sont échappés ; 5/5 tests de durcissement réussis.

### 4.2 Mass Assignment Prevention (`incidents/forms.py`)
- **Risque**: Injection de paramètres `status="resolved"` ou `created_by=<target_id>` dans les formulaires POST pour s'octroyer des droits ou clore un incident sans intervention d'un analyste.
- **Remediation**: 
  - Déclaration explicite : `fields = ["title", "description", "severity"]`.
  - Attribution immuable du créateur côté serveur : `form.instance.created_by = self.request.user`.
  - Initialisation forcée du statut à `OPEN`.

### 4.3 State Transition Machine (`incidents/models.py`)
- **Risque**: Saut direct d'un incident de `OPEN` à `RESOLVED` ou modification non autorisée d'un incident clôturé.
- **Remediation**: Matrice de transitions permises :
```python
ALLOWED_TRANSITIONS = {
    Status.OPEN: {Status.OPEN, Status.IN_PROGRESS, Status.CLOSED},
    Status.IN_PROGRESS: {Status.IN_PROGRESS, Status.RESOLVED, Status.CLOSED, Status.OPEN},
    Status.RESOLVED: {Status.RESOLVED, Status.CLOSED, Status.IN_PROGRESS},
    Status.CLOSED: {Status.CLOSED, Status.OPEN},
}
```
Toute tentative non autorisée est rejetée au niveau du modèle via `clean()` avec une `ValidationError`.

### 4.4 Stored XSS Neutralization in Comments
- **Risque**: Injection de scripts malveillants (`<script>alert(1)</script>`) dans les commentaires stockés en base, exécutés lors de la consultation par l'analyste.
- **Remediation**:
  - Validation de type texte brut (2 à 2000 caractères).
  - Rendu strict sans filtre `|safe` dans les templates Django, activant l'auto-échappement contextuel HTML (`&lt;script&gt;`).
  - Entête HTTP `Content-Security-Policy: default-src 'self'; script-src 'self'`.

### 4.5 Audit Logging Without Secret Leakage (`incidents/audit.py`)
- **Risque**: Journalisation accidentelle de mots de passe ou tokens dans les fichiers de logs.
- **Remediation**:
  - Modèle d'audit `AuditEvent` traçant les actions critiques avec adresse IP et identifiant.
  - Filtre d'assainissement automatique supprimant tout secret potentiel avant persistance.

---

## 5. Security Pipeline & Scanner Verification

### 5.1 Static Analysis (SAST) — Semgrep
- **Règles exécutées**: 339 règles couvrant OWASP Top 10, bonnes pratiques Django et sécurité Python.
- **Finding réel détecté & corrigé**:
  - Fichier: `training/management/commands/seed_security_lab.py`
  - Alerte: `python.django.security.audit.unvalidated-password` (mot de passe initialisé sans validation).
  - Correction: Intégration de `validate_password(raw_password, user=user)`.
- **Résultat final**: **0 findings (100% propre)**.

### 5.2 Software Composition Analysis (SCA) — `pip-audit`
- **Portée**: Dépendances de production [`requirements.txt`](../requirements.txt).
- **Résultat**: **No known vulnerabilities found** (0 CVE).

### 5.3 Secret Scanning — TruffleHog
- Analyse de l'historique Git et vérification de l'absence de clés API, tokens de session ou mots de passe commités.
- `.env` et fichiers de base de données locales strictement ignorés par `.gitignore`.

### 5.4 Dynamic Analysis (DAST) — OWASP ZAP
- Intégration du job CI `dast-zap-scan` avec `zaproxy/action-baseline@v0.14.0`.
- Analyse dynamique des routes HTTP et vérification de la présence des en-têtes défensifs (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`).

---

## 6. Release Gate Policy & Rollback Procedure

### 6.1 Critères de validation avant mise en production (Release Gate)
Aucune modification n'est déployée si l'une des conditions suivantes échoue :
1. ✅ **Tests unitaires et d'isolation (SQLite)** : 100% de réussite.
2. ✅ **Tests d'intégration PostgreSQL** : 100% de réussite.
3. ✅ **Gate de durcissement SQLi** : 5/5 tests de durcissement passants.
4. ✅ **Scan SAST Semgrep** : 0 alerte bloquante.
5. ✅ **Audit de dépendances pip-audit** : 0 CVE connue.
6. ✅ **Vérification des secrets TruffleHog** : 0 secret détecté.
7. ✅ **Dry-run des migrations** : `makemigrations --check --dry-run` ne signale aucun changement manquant.

### 6.2 Procédure de Rollback (Plan de retour arrière)
En cas d'anomalie détectée en production sur Vercel :
1. **Rollback applicatif instantané** : Dans le dashboard Vercel, sélectionner le dernier déploiement stable antérieur et cliquer sur **Instant Rollback**.
2. **Rollback Git** :
   ```bash
   git revert <commit_hash>
   git push origin master
   ```
3. **Rollback de base de données (si migration appliquée)** :
   ```bash
   python manage.py migrate incidents <migration_precedente>
   ```

---

## 7. Bilan des Tests Automatisés

```text
Ran 61 tests in 4.10s
OK (skipped=5 in isolated test mode; 5/5 passed in security lab mode)
```
- **12 tests** de matrice de rôles et déni d'accès (`test_roles.py`).
- **7 tests** anti-XSS, CSRF et journalisation d'audit (`test_audit_and_xss.py`).
- **6 tests** de protection contre la force brute et rate limiting (`test_ratelimit.py`).
- **6 tests** de cycle de vie et transitions d'états (`IncidentLifecycleAndValidationTests`).
- **25 tests** de sécurité de base (sessions, CSP, headers no-store, configuration de production).
- **5 tests** de durcissement contre l'injection SQL (`test_hardening.py`).

---

## 8. Conclusion

Le projet **Incident Desk** répond à l'ensemble des exigences académiques et techniques du capstone de sécurité applicative. Les défenses implémentées combinent des protections au niveau du modèle de données (ORM paramétré, machine à états), de la couche de transport et de session (cookies sécurisés, tokens CSRF, headers CSP), de l'interface utilisateur (auto-échappement strict), et de la chaîne d'intégration continue automatisée.
