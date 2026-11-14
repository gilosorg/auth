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

## 4. UI Engineering & Brand Design Rules (CRITICAL)

### Sharp `0px` Geometry (Brand Face — MANDATORY)
- Every UI element across this service MUST have square edges (`border-radius: 0px`).
- Never use `border-radius > 0`, `50%`, or pill radii (`9999px`) on cards, containers, inputs, textareas, selects, buttons, checkboxes, radio buttons, toggle switches, badges, pills, avatars, skeletons, scrollbars, toast popups, modals, HTML OTP emails, or inline JS markup.
- All radius tokens in `static/css/app.css` (`--radius-xs`, `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-xl`, `--radius-pill`) MUST remain `0px`.
- When integrating third-party UI libraries (SweetAlert2 `.swal2-*`, `intl-tel-input` `.iti__*`, CropperJS `.cropper-*`), explicitly override their corner radii with `border-radius: 0px !important`.

### Form Controls & Interactive Primitives
- Enforce `button, input, textarea, select { border-radius: 0px; }` globally.
- Always style `input[type="checkbox"]` and `input[type="radio"]` using `appearance: none; -webkit-appearance: none; border-radius: 0px;` (crisp square frame with angled checkmark for checkboxes, centered inner square for radios), leaving `.toggle-switch` as a rectangular track with a sliding square thumb.
- Rely on crisp `1px`/`1.5px` borders (`--border-subtle`, `--border-default`, `--border-strong`), spacing hierarchy, and elevation shadows for visual structure rather than rounded corners or ornamental blurs.

### Themes, Tokens & Maintainability
- Build strictly with vanilla HTML/CSS/JS; do not add CSS frameworks.
- Always consume CSS custom properties from `static/css/app.css` and verify every new component works cleanly in both Light mode and Dark mode (`:root[data-theme="dark"]` and `@media (prefers-color-scheme: dark)`).
- Keep `:focus-visible` outlines clear (`2px solid var(--accent)`), maintain responsive behavior at mobile breakpoints (`375px`+), respect `prefers-reduced-motion`, and update all three translation files (`i18n/translations/en.json`, `ru.json`, `uz.json`) when adding user-facing copy.

### Identity Naming (Username vs. User ID)
- Always call the `@username` login handle **"Gilos Username"** (or **"Username"** / placeholder **"Enter username"**; configured via `APP_ID_LABEL="Gilos Username"`).
- Call the authentication service/portal **"Gilos Auth"** (`APP_NAME="Gilos Auth"`).
- Reserve **"User ID"** exclusively for numeric database IDs (e.g., `User ID: #1`).
- Never reintroduce `"Gilos ID"` or call `@username` an "ID" in UI labels, placeholders, error messages, SMS copy, emails, or documentation.
