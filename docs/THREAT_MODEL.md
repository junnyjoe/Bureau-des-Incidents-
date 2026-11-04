# Initial threat-model worksheet (v1)

## System boundary

Browser → Django application → PostgreSQL. Administrative user provisioning is through Django admin. GitHub Actions builds/tests code, and Vercel serves a released revision. Database credentials and the stable Django signing key are environment configuration. Identify where trust/privileges change, not just machine/container boundaries.

## Assets and evidence

| Asset | Existing control | What remains to verify/extend |
|---|---|---|
| Incident content | Owner-scoped queryset; server-assigned owner | Analyst/admin policy and its negative tests |
| Credentials/sessions | Django hashing/session/CSRF facilities | Backoff, operational monitoring, deployed cookie/session evidence |
| Signing key and DB access | Environment variables; fail-closed production config | Rotation/recovery procedures, least DB privilege, repository/history scan |
| Source/release integrity | Pinned dependency snapshot; baseline tests | SAST/SCA/secrets/DAST, protected release and supply-chain decisions |

## Threat table to complete

| ID / STRIDE | Asset and DFD element | Scenario and evidence/assumption | Likelihood | Impact | Proposed control | Verification | Status |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

State scoring assumptions and prioritize six threats; do not merely copy scanner categories. Preserve this baseline, expand for new features and deployment, and attach implementation/test evidence to the final statuses. Document accepted/open risk rather than pretending every course topic must become an implemented feature.
