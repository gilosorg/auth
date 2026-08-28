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
- **Automated Deployment**: Deployments to production are triggered automatically when a new GitHub Release (Git tag `v*`) is created.
  - When you push to `main`, a Release PR is automatically created/updated.
  - Do **not** deploy manually. Simply push your conventional commits to `main` and let the Release Please workflow handle the versioning.
