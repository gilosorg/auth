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

## 4. SMS Delivery & Verified Template (Eskiz — IMMUTABLE)
- Eskiz strictly enforces pre-approved verified SMS text only. Never alter, translate, paraphrase, or rebrand a single word of the verified template:
  `auth.gilos.org is sending this code to verify your phone for Gilos ID registration or access: <6-digit-code>`
- Use this exact wording identically across **all** verification cases (registration, MFA, contact verification, password recovery) and **all** user languages (`en`, `ru`, `uz`), managed via `FormatPhoneOTPMessage` in `utils/send_phone_otp.go`.
- Preserve `"Gilos ID"` verbatim inside this carrier-whitelisted SMS template; it is an intentional immutable exception to the UI naming rule in Section 5.

## 5. UI Engineering & Brand Design Philosophy (CRITICAL)

Gilos interfaces follow the **Microsoft Fluent 2 (Windows 11 Settings)** design system: Mica ambient layering (`#F3F3F3` Light / `#202020` Dark canvases with soft ambient glow and **zero** mathematical/wireframe background grid lines), crisp `1px` SettingsCard elevation (`#FFFFFF` Light / `#2B2B2B` Dark), Acrylic frosted overlays (`backdrop-filter: blur(30px) saturate(165%)`), generous calm spacing, natural optical corner radii, and clean typographic hierarchy.

### Fluent 2 Corner Geometry & Natural Micro-Indicators (MANDATORY)
- **Layered Radius Hierarchy**:
  - `--radius-xs`: `2px` (keyboard shortcut badges, inline code chips)
  - `--radius-sm`: `4px` (buttons, inputs, selects, checkboxes, navigation rows, copy/action buttons)
  - `--radius-md`: `6px` (callout InfoBars, OTP digit cells, grouped rows, inner panels)
  - `--radius-lg` / `--radius-xl`: `8px` (cards, SettingsCards, dialogs/modals, Acrylic dropdowns/flyouts, toasts, HTML OTP email containers)
  - `--radius-pill`: `9999px` (toggle switches, search pills, active nav selection indicator pills, status badges/chips)
  - **`50%` Circular**: User profile avatars (header, navigation rail, hero profile, OAuth consent preview), radio inputs (`input[type="radio"]`), step numbers, rotating spinners (`.spinner`, `.btn-spinner`), and status dots (`.status-live-dot`, `.pw-rule-dot`).
- **No Brutalist `0px` Containers or Background Grid Lines**: Do **not** revert UI cards, inputs, modals, buttons, or HTML OTP emails to `0px` square geometry, and do **not** render mathematical grid-paper backgrounds. Keep third-party library overrides (SweetAlert2 `.swal2-*`, `intl-tel-input` `.iti__*`) harmonized with Fluent `4px`/`6px`/`8px` tokens (`--radius-sm`, `--radius-lg`) and keep CropperJS avatar cropper points circular/rounded.
- **Navigation Selection Indicator**: Use Windows 11 Settings active indicators (`3px × 16px` vertical left pill `border-radius: 9999px` in `var(--accent)` for vertical rails/sidebars/option lists, or centered `3px` bottom pill indicator for horizontal tabs/pivots).

### Unified Flex Input Groups & WinUI Bottom-Accent Stroke (CRITICAL)
- **NEVER** position icon/text prefixes, status indicators, eye toggles, or submit buttons inside `<input>` via `position: absolute` with hardcoded `padding-left`/`padding-right` (font and glyph metrics vary and cause baseline sag, tight kerning, and uneven gaps).
- **ALWAYS** construct bordered flex input groups (`display: flex; align-items: stretch; border: 1px solid var(--border-default); border-bottom: 1.5px solid var(--input-stroke-bottom); border-radius: var(--radius-sm); background: var(--surface-elevated); overflow: hidden;`):
  - Place Fluent UI icon prefixes (such as `person` inside `.gilos-input-addon.gilos-input-addon--icon` rather than raw `@` characters) in a stretch-height left addon cell centered on the exact cross-axis as a borderless `flex: 1; min-width: 0` `<input>`.
  - Dock trailing actions (submit buttons, password visibility toggles, clear actions) cleanly at the trailing edge of the flex group (`height: 100%`, `border-left: 1px solid var(--border-subtle)`), styled intentionally when disabled (subtle matte surface and `var(--text-tertiary)` icon color).
  - Apply hover (`border-color: var(--border-strong)`) and `:focus-within` (`border-bottom-color: var(--accent); box-shadow: inset 0 -1px 0 0 var(--accent);`) on the outer wrapper rather than the inner borderless `<input>`. Apply the same WinUI `1.5px` bottom-accent focus stroke on standalone `.auth-input`, `.console-input`, `.console-select`, `.otp-input`, and search inputs.

### Structural Balance, Typography & Deterministic Kinematics
- **Mica Surfaces & Fluent Accents**: Consume CSS variables from `static/css/app.css` (`#005FB8` primary accent with `#FFFFFF` contrast text in Light Mode; `#60CDFF` primary accent with `#000000` contrast text in Dark Mode). Never add heavy `border-top: 2px solid` stripes onto cards or modals—use subtle `1px solid var(--card-border)` elevation and soft `--card-shadow` / `--modal-shadow`.
- **Hierarchy & Monospace Discipline**: Use `'Segoe UI Variable', 'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif` with `600` (SemiBold) Windows 11 headings. Always verify text contrast tokens (`--text`, `--text-secondary`, `--text-muted`, `--text-tertiary`) in both Light and Dark themes. Render usernames and identity handles in proportional sans-serif (never monospace), and pair sans-serif with `var(--font-mono)` (`'JetBrains Mono'`, system monospace) plus `font-variant-numeric: tabular-nums` exclusively for technical values: numeric `User ID #...`, OTP digit grids, countdowns, client IDs/secrets, scopes, IP addresses, and HTTP status pills.
- **Line Wrapping & Kinematics**: Constrain centered disclaimer/legal text (`max-width: 310px`–`340px`) to avoid single-word orphan wraps. Prefer subtle WinUI surface/tonal transitions and crisp `translateY(1px)` click detents over bouncy scale animations.

### Form Controls, Themes & Maintainability
- Enforce `border-radius: var(--radius-sm)` globally on `button, input, textarea, select` (except `input[type="radio"]`, which stays `50%` circular).
- Style `input[type="checkbox"]` with `border-radius: var(--radius-sm)` (`4px`) and angled checkmark, `input[type="radio"]` as `50%` circular with centered dot, and `.toggle-switch` as a WinUI `9999px` pill track (`1px` border) with a circular sliding thumb (`50%`).
- Build strictly with vanilla HTML/CSS/JS; do not add CSS frameworks.
- Verify every new component in both Light mode and Dark mode (`:root[data-theme="dark"]` and `@media (prefers-color-scheme: dark)`), keep `:focus-visible` outlines clear (`2px solid var(--accent)`), maintain responsive behavior at mobile breakpoints (`375px`+), respect `prefers-reduced-motion`, and update all three translation files (`i18n/translations/en.json`, `ru.json`, `uz.json`) when adding user-facing copy.

### Identity Naming (Username vs. User ID)
- Always call the username login handle **"Gilos Username"** (or **"Username"** / placeholder **"Enter username"**; configured via `APP_ID_LABEL="Gilos Username"`).
- Call the authentication service/portal **"Gilos Auth"** (`APP_NAME="Gilos Auth"`).
- Reserve **"User ID"** exclusively for numeric database IDs (e.g., `User ID: #1`).
- Never reintroduce `"Gilos ID"` or call the username an "ID" in UI labels, placeholders, error messages, emails, or documentation (the sole exception is the immutable Eskiz carrier-approved SMS template in Section 4 above).
