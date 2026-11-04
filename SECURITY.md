# Course security scope

This starter is for synthetic classroom incident records. Its private-record behavior has automated tests; it is not certified for handling real security incidents or personal information.

Framework-provided authentication, CSRF protection, ORM binding and template escaping are enabled. Application ownership is enforced on server queries. Production settings require PostgreSQL, private environment configuration and explicit HTTPS origins/hosts. Django superusers can administer records through the separately protected administration site.

Known capstone work includes login throttling/backoff, analyst and business-admin policy, audit events, operational monitoring, dependency/secret scans, authenticated DAST, migration/recovery procedures and verified production release gating. Password recovery and file uploads are not implemented. Keep intentionally exploitable exercises local and separate from the deployed starter.

Never report a real secret by committing it or placing it in an issue/screenshot. Revoke/rotate an exposed credential at its issuer and investigate source history, artifacts and logs. Review supported package versions and platform policies before each cohort.

See docs/DEPLOYMENT.md and docs/MILESTONES.md for configuration limits and verification requirements.

An intentionally vulnerable SQL search is included only in the separate training module and local config.settings.security_lab mode. Never select that mode for deployment. Ordinary routes omit it; production sets TRAINING_MODE=False. Run its separate acceptance gate when assessing remediation; a green baseline test run does not establish that the opt-in challenge was fixed.
