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

## 4. UI Engineering & Brand Design Philosophy (CRITICAL)

Gilos interfaces blend clean, approachable SaaS clarity (generous breathing room, soft rounded geometry, crisp `1px` borders, clear visual hierarchy) with Apple-inspired consumer calm (understated typography, translucent surfaces, tactile restraint, and natural human iconography). Controls should feel familiar, cohesive, and intuitive.

### Rounded Geometry & Natural Iconography (MANDATORY)
- **Containers & Interactive Surfaces**: Use standard rounded radius tokens in `static/css/app.css`:
  - `--radius-xs: 4px` (checkboxes, subtle inline badges/flags)
  - `--radius-sm: 8px` (buttons, inputs, textareas, selects, nav pills, list rows)
  - `--radius-md: 10px` (toasts, dropdown menus, code blocks, callouts)
  - `--radius-lg: 14px` (cards, entity tiles, modals)
  - `--radius-xl: 16px` (primary auth/OAuth stage cards, legal sheet)
  - `--radius-pill: 9999px` (status badges, toggle switches, filter pills, avatars, chips)
- When integrating third-party UI libraries (SweetAlert2 `.swal2-*`, `intl-tel-input` `.iti__*`, CropperJS `.cropper-*`), match these standard rounded tokens (`var(--radius-lg)` for dialogs, `var(--radius-md)` for dropdown panels, `var(--radius-sm)` for inputs/buttons) and preserve natural circular warning/success icons.
- **Icons, Spinners & Avatars**: Keep pictographic SVG icons natural (`rx="2"` on hardware/document rects, round stroke caps/joins). User avatars (`.avatar-circle`, `.user-trigger-avatar`, `.identity-chip-avatar`), spinners (`.spinner`, `.btn-spinner`), radio buttons (`input[type="radio"]`), toggle knobs, and status dots (`.status-live-dot`, `.pw-rule-dot`) use smooth circles (`border-radius: 50%`).

### Unified Flex Inputs & Clean Inline Adornments (CRITICAL)
- **NEVER** position text prefixes (`@`), status indicators, eye toggles, or submit buttons inside `<input>` via `position: absolute` with hardcoded `padding-left`/`padding-right` (font metrics vary across glyphs such as Inter `@` vs `E` and cause baseline sag, tight kerning, and uneven top/right/bottom air gaps).
- **ALWAYS** construct bordered flex input groups (`display: flex; align-items: center; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-elevated); overflow: hidden`):
  - Place inline sigils (`@` in `var(--font-mono)`) or search icons smoothly inline inside the input (`padding-left: 13px; padding-right: 4px; background: transparent; border-right: none`) aligned cleanly on the cross-axis before a borderless `flex: 1; min-width: 0` `<input>` (avoid hard vertical divider boxes).
  - Tuck trailing actions (password visibility toggles, clear icons, compact primary arrow submit buttons) neatly inside the right edge (`margin: 4px; border-radius: 6px; border: none`) so inputs feel unified and effortless.
  - Style disabled inline submit buttons cleanly (`background: var(--surface-subtle); color: var(--text-tertiary)`).
  - Apply hover, `:focus-within` (`border-color: var(--accent)`, `box-shadow: 0 0 0 2px var(--focus-ring)`), and error rings on the outer wrapper rather than the inner borderless input.

### Structural Balance, Typography & Deterministic Kinematics
- **Calm Navigation & Segmented Controls**: Prefer clean spacing (`gap: 4px`–`8px`) and soft pill highlights (`.header-tabs`, `.filter-pills`, `.legal-nav`) or subtle segmented pill tracks (`.method-selector`) and individual rounded option cards (`.radio-option`) over joined table-like box strips.
- **Hierarchy & Monospace Discipline**: Always define and verify text contrast tokens (`--text`, `--text-secondary`, `--text-muted`, `--text-tertiary`) in both Light and Dark themes so footer disclaimers, placeholders, and prefixes remain subtle yet legible. Pair `Inter` with `var(--font-mono)` (`'JetBrains Mono'`, system monospace) and `font-variant-numeric: tabular-nums` for `@` handles, numeric `User ID #...`, OTP digit grids, countdowns, client IDs, scopes, and HTTP status tags.
- **Line Wrapping & Kinematics**: Constrain centered disclaimer/legal text (`max-width: 310px`–`340px`) to avoid single-word orphan wraps. Prefer subtle border/tonal transitions and crisp `translateY(1px)` click detents over bouncy scale animations.

### Form Controls, Themes & Maintainability
- Enforce `button, input, textarea, select { border-radius: var(--radius-sm); }` globally (keeping `input[type="radio"]` as `50%` and `input[type="checkbox"]` as `var(--radius-xs)` / `4px`).
- Style `input[type="checkbox"]` (`border-radius: var(--radius-xs)` with angled checkmark), `input[type="radio"]` (`appearance: none; border-radius: 50%` with centered circular dot), and `.toggle-switch` as a modern pill switch (`border-radius: var(--radius-pill)` track with circular `50%` sliding thumb).
- Build strictly with vanilla HTML/CSS/JS; do not add CSS frameworks.
- Always consume CSS custom properties from `static/css/app.css` and verify every new component works cleanly in both Light mode and Dark mode (`:root[data-theme="dark"]` and `@media (prefers-color-scheme: dark)`).
- Keep `:focus-visible` outlines clear (`2px solid var(--accent)`), maintain responsive behavior at mobile breakpoints (`375px`+), respect `prefers-reduced-motion`, and update all three translation files (`i18n/translations/en.json`, `ru.json`, `uz.json`) when adding user-facing copy.

### Identity Naming (Username vs. User ID)
- Always call the `@username` login handle **"Gilos Username"** (or **"Username"** / placeholder **"Enter username"**; configured via `APP_ID_LABEL="Gilos Username"`).
- Call the authentication service/portal **"Gilos Auth"** (`APP_NAME="Gilos Auth"`).
- Reserve **"User ID"** exclusively for numeric database IDs (e.g., `User ID: #1`).
- Never reintroduce `"Gilos ID"` or call `@username` an "ID" in UI labels, placeholders, error messages, SMS copy, emails, or documentation.
