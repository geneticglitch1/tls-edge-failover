# Publish your copy on GitHub

Publish only this sanitized source folder. Do not upload an older deployment folder, attachments, terminal logs, `runtime/`, system configuration, or backups. No real deployment values are needed on GitHub or in GitHub Actions secrets.

## Use the prepared local repository

The delivered local repository has a fresh `main` branch, a generic initial author, and no remote. It does not contain previous deployment history. From that repository folder:

```bash
git status --short
git log -1 --format=fuller
git ls-files
```

Review these outputs. The initial identity is a generic project identity, not a personal name/email. To use your own identity for future commits, configure a public display name and your GitHub-provided **noreply** email locally; do not paste a private email if you want it kept out of commits.

Create an **empty** GitHub repository named `tls-edge-failover` (or your preferred name). Do not initialize it with another README, license, or `.gitignore`; these are already included. Choose its visibility in GitHub.

Copy its HTTPS or SSH URL, then in Bash:

```bash
read -r -p 'GitHub repository URL: ' REPO_URL
git remote add origin "$REPO_URL"
git push -u origin main
```

Authenticate with your normal GitHub method. Do not put a token in the URL or a tracked file. These instructions assume no existing `origin`; inspect `git remote -v` before changing an established repository.

## If you downloaded the source ZIP

The ZIP contains the same tracked source, including `.github/` and `.gitignore`, but deliberately excludes `.git` history and runtime files. Extract it into a new folder. You can upload the extracted source using GitHub's web interface, ensuring hidden files are included, or initialize Git locally:

```bash
git init -b main
git config user.name 'TLS Edge Failover contributors'
git config user.email 'contributors@example.invalid'
git add .
git diff --cached --stat
git diff --cached
git commit -m 'Initial TLS edge failover source'
```

Use the repository URL/push steps above. You can substitute your preferred public identity and GitHub noreply email before the initial commit.

## Before every publication

- Review `git diff --cached` and `git ls-files` for domains, IPs, IDs, tokens, keys, logs, and local paths introduced by later changes.
- Keep the tracked example JSON as placeholders; configure real installations in ignored paths.
- Confirm runtime files are ignored with `git check-ignore runtime/watchdog.json runtime/cf-token runtime/watchdog.log runtime/haproxy.cfg`.
- If secrets were previously committed, remove them from the history you intend to publish and revoke any real credential. Ignoring the filename does not repair existing history.
- Keep GitHub Actions free of production DNS credentials. Its tests use fixtures and do not deploy anything.

The included MIT license covers this source. Review it before publishing your copy. GitHub's **Actions** tab will show CI results after the first push; local test success does not mean a workflow has already run on GitHub.
