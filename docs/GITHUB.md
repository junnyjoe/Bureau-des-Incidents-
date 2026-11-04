# First personal GitHub repository

Do this in an extracted standalone copy of Incident Desk. If the instructor publishes a GitHub template, use **Use this template → Create a new repository** and clone your personal copy instead. Preserve hidden .github/.gitignore files.

1. On GitHub, create a personal repository called incident-desk. An empty repository is simplest; do not create another README when importing these files.
2. In a terminal open the folder containing manage.py, then:

```bash
git init -b main
git add .
git status
```

3. Inspect the staged paths. Do not stage .env, .venv, staticfiles or a database. You can run `git check-ignore .env` after creating .env. If a real secret was ever committed, removing it is insufficient: rotate/revoke it and investigate copies/history.
4. Commit and connect your actual personal repository URL (replace the placeholder):

```bash
git commit -m "Start Incident Desk with private incident workflow"
git remote add origin https://github.com/YOUR_USERNAME/incident-desk.git
git push -u origin main
```

Authenticate using GitHub's supported browser/credential-manager flow. Do not paste access tokens into repository URLs or source.

5. Open GitHub → Actions → starter-tests. Confirm both jobs run and read their logs. The included workflow is a test baseline, not yet a complete security pipeline.
6. For each milestone create a branch, commit small changes, push, open a pull request, review checks, and merge through the course's agreed process. Do not fabricate screenshots when an external run is pending.

Use your own Hobby account and repository for Vercel. Hobby Git deployment has ownership/commit-author and private-organization constraints; confirm your course setup against current documentation. Pair discussion is fine, but avoid assuming a paid shared deployment team.

Reference: https://vercel.com/docs/git
