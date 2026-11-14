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

Gilos interfaces blend **corporate Microsoft / Fluent structural discipline** (sharp rectangular containers, crisp hairline borders, clear grid hierarchy) with **Apple-inspired consumer calm** (generous breathing room, understated typography, translucent surfaces, tactile restraint, and natural human iconography). Square UI boxes should feel purposeful and modern—never brutalist, sterile, or robotic.

### Sharp `0px` Box Geometry & Natural Iconography (Brand Face — MANDATORY)
- **Containers & Interactive Surfaces (`0px`)**: Cards, containers, panels, inputs, textareas, selects, buttons, checkboxes, toggle switches, badges, status tags, avatars, dropdown menus, skeletons, scrollbars, toast popups, modals, and HTML OTP emails MUST have sharp square corners (`border-radius: 0px`).
- All radius tokens in `static/css/app.css` (`--radius-xs`, `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-xl`, `--radius-pill`) MUST remain `0px`.
- When integrating third-party UI libraries (SweetAlert2 `.swal2-*`, `intl-tel-input` `.iti__*`, CropperJS `.cropper-*`), explicitly override container/control corner radii with `border-radius: 0px !important`.
- **Icons, Spinners & Semantic Dots Stay Natural**: **Do NOT** force `0px` blocky geometry onto icons or inherently circular micro-indicators. Pictographic SVG icons (devices, locks, envelopes, copy symbols, badges, shields) should preserve natural optical rounding (`rx="2"` on hardware/document rects, round stroke caps/joins). Rotating spinners (`.spinner`, `.btn-spinner`), radio buttons (`input[type="radio"]`), and tiny status dots (`.status-live-dot`, `.pw-rule-dot`) remain smoothly circular (`border-radius: 50%`) so icons read as icons and status cues stay human.

### Unified Flex Input Groups & Flush Adornments (CRITICAL)
- **NEVER** position text prefixes (`@`), status indicators, eye toggles, or submit buttons inside `<input>` via `position: absolute` with hardcoded `padding-left`/`padding-right` (font metrics vary across glyphs such as Inter `@` vs `E` and cause baseline sag, tight kerning, and uneven top/right/bottom air gaps).
- **ALWAYS** construct bordered flex input groups (`display: flex; align-items: stretch; border: 1.5px solid var(--border-default); background: var(--surface-subtle)`):
  - Place static sigils (`@` in `var(--font-mono)`) in a stretch-height left addon cell (`flex: 0 0 40px`–`42px`, `border-right: 1px solid var(--border-default)`, subtle tonal fill) centered on the exact cross-axis as a borderless `flex: 1; min-width: 0` `<input>`.
  - Dock trailing actions (submit buttons, password visibility toggles, clear actions) **flush** to the top, right, and bottom borders (`height: 100%`, `border-left: 1px solid var(--border-default)`), never floating inside an input with gaps.
  - Style disabled docked buttons as intentional matte structural cells (`opacity: 1` with subtle background and `var(--text-tertiary)` icon color) rather than faded translucent boxes.
  - Apply hover, `:focus-within` (`border-color: var(--accent)`, `box-shadow: 0 0 0 2px var(--focus-ring)`), and error rings on the outer wrapper rather than the inner borderless input.

### Structural Balance, Typography & Deterministic Kinematics
- **Structured Calm**: Combine `1px` corporate hairlines, `gap: 0` segmented bars (`.method-selector`, `.filter-pills`), and `inset 3px 0 0` / `inset 0 -2px 0` active accent rails with subtle, restrained surface depth (`--card-shadow`, frosted translucent headers) and open padding so interfaces remain calm and breathable.
- **Hierarchy & Monospace Discipline**: Always define and verify text contrast tokens (`--text`, `--text-secondary`, `--text-muted`, `--text-tertiary`) in both Light and Dark themes so footer disclaimers, placeholders, and prefixes remain subtle yet legible. Pair `Inter` with `var(--font-mono)` (`'JetBrains Mono'`, system monospace) and `font-variant-numeric: tabular-nums` for `@` handles, numeric `User ID #...`, OTP digit grids, countdowns, client IDs, scopes, and HTTP status tags.
- **Line Wrapping & Kinematics**: Constrain centered disclaimer/legal text (`max-width: 310px`–`340px`) to avoid single-word orphan wraps. Prefer subtle border/tonal transitions and crisp `translateY(1px)` click detents over bouncy scale animations.

### Form Controls, Themes & Maintainability
- Enforce `button, input, textarea, select { border-radius: 0px; }` globally (except `input[type="radio"]`, which keeps its classic `50%` circular ring so users can immediately distinguish single-choice radios from square multi-select checkboxes).
- Style `input[type="checkbox"]` (`border-radius: 0px` with angled checkmark) and `input[type="radio"]` (`appearance: none; border-radius: 50%` with centered circular dot), leaving `.toggle-switch` as a `1px`-bordered rectangular track with an exact-fit sliding square thumb.
- Build strictly with vanilla HTML/CSS/JS; do not add CSS frameworks.
- Always consume CSS custom properties from `static/css/app.css` and verify every new component works cleanly in both Light mode and Dark mode (`:root[data-theme="dark"]` and `@media (prefers-color-scheme: dark)`).
- Keep `:focus-visible` outlines clear (`2px solid var(--accent)`), maintain responsive behavior at mobile breakpoints (`375px`+), respect `prefers-reduced-motion`, and update all three translation files (`i18n/translations/en.json`, `ru.json`, `uz.json`) when adding user-facing copy.

### Identity Naming (Username vs. User ID)
- Always call the `@username` login handle **"Gilos Username"** (or **"Username"** / placeholder **"Enter username"**; configured via `APP_ID_LABEL="Gilos Username"`).
- Call the authentication service/portal **"Gilos Auth"** (`APP_NAME="Gilos Auth"`).
- Reserve **"User ID"** exclusively for numeric database IDs (e.g., `User ID: #1`).
- Never reintroduce `"Gilos ID"` or call `@username` an "ID" in UI labels, placeholders, error messages, SMS copy, emails, or documentation.
