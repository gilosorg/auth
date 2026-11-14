# AI Agent Instructions

This document provides strict guidelines and context for any AI agents working on this repository.

## 1. Copyright and Identity (CRITICAL)
- **DO NOT** inject your own name, AI company name, or placeholder names into comments, code, or copyright headers.
- **DO NOT** modify the copyright, license, or trademark statements. The user strictly despises AI copyright sharing. 
- Keep the code entirely devoid of any AI footprint. Write code as if a human engineer at the company wrote it.

## 2. Git Workflow & Deployment
- **Environment**: Development happens directly on the live server.
- **Git Operations**: Use standard Git commands (`git add`, `git commit`, `git push`) or the GitHub CLI (`gh`).
- **Commit Messages (CRITICAL)**: You MUST use Conventional Commits. The repository uses `release-please` to automatically generate semantic version releases.
  - `feat: ` for new features (MINOR bump).
  - `fix: ` for bug fixes (PATCH bump).
  - `feat!: ` or `fix!: ` for breaking changes (MAJOR bump).
  - `chore: `, `docs: `, `refactor: ` for other changes.
- **Automated Deployment**: Deployments to production are triggered automatically when you push to the `main` branch. 
  - The `release-please` action will also run to generate releases and version tags on GitHub for documentation, but the live server simply stays on the `main` branch to avoid disrupting active development.
  - Do **not** deploy manually. Simply push your conventional commits to `main` and let the workflows handle it.

## 3. Email Domains & Support Contacts (Resend)
Email domains in Resend are separated by purpose to protect deliverability and isolate automated transactional traffic from corporate correspondence:

- **`auth.gilos.org` (Sending Only — Transactional Auth Emails)**:
  - Configured on Resend with **sending enabled** and **receiving disabled**.
  - Used exclusively by this service via `RESEND_FROM_EMAIL` in server `.env` (set to `"Gilos Auth <noreply@auth.gilos.org>"`) to deliver OTP and verification emails.
  - Do **not** configure receiving/support addresses on `auth.gilos.org` or send automated auth emails from the apex domain `gilos.org`.
- **`gilos.org` (Send & Receive — Corporate & Support Correspondence)**:
  - Configured on Resend with both **sending and receiving enabled**.
  - Reserved exclusively for direct communication with clients, corporate tasks, support, and security inquiries (`info@gilos.org`).
  - All public contact, legal, and security reporting references across both the `auth` project (e.g., `SECURITY.md`) and `gilos.org` must point to `info@gilos.org`. Do **not** route automated auth emails through `gilos.org`.
- **`mail.gilos.org` & `info@gilos.email` (Decommissioned)**:
  - Both domains/addresses have been retired and deleted from Resend. Never reference `mail.gilos.org` or `info@gilos.email` in code, configuration, tests, templates, or documentation.
