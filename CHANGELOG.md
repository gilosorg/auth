# Changelog

## [0.2.0](https://github.com/gilosorg/auth/compare/v0.1.6...v0.2.0) (2026-11-14)


### Features

* add modal focus trapping, proxy error resilience, and docs oauth debugger ([bbdb7e0](https://github.com/gilosorg/auth/commit/bbdb7e037904513c227303d4ebe4a72af4e8edb4))
* add theme switcher, localized legal pages and OAuth 2.1 docs improvements ([2ad1967](https://github.com/gilosorg/auth/commit/2ad1967049beae37ca9fa5ccd293a71b56e643d1))
* bypass rate limiting for health/static, expand CORS headers and default PKCE to S256 ([037205c](https://github.com/gilosorg/auth/commit/037205cce9911f984670b804db130497c55c6a1c))
* elevate brand logo framing and polish auth and docs UX ([527a57d](https://github.com/gilosorg/auth/commit/527a57d587d79c8496ad00f752c1c8a0e9c5b2a5))
* elevate dark-mode parity, OTP autofill, and segmented portal architecture ([33bf2cd](https://github.com/gilosorg/auth/commit/33bf2cd601a597f1450c420f8ce9725ddf8944e9))
* elevate UI with Acrylic glass surfaces, architectural grid canvas, and Fluent UI icons ([be82e3b](https://github.com/gilosorg/auth/commit/be82e3b3ac3e2d6cf1d6a3c2735bdc6653cf70dc))
* enforce sharp 0px UI geometry and clarify username terminology ([03ad4c9](https://github.com/gilosorg/auth/commit/03ad4c9b69e52a9967cd787aa373d8c0a20a2bc0))
* enhance OAuth loopback validation, add logout endpoint, and enable TOTP encryption ([d5c40cd](https://github.com/gilosorg/auth/commit/d5c40cdd14e188eb504524d4fa73f12a146f6784))
* enhance UI/UX accessibility, responsiveness, and translations across pages ([68663ad](https://github.com/gilosorg/auth/commit/68663ad56bb0bdff421d1a1cf7ee004ba83c86fd))
* fix OAuth clients loading and enhance console search, filtering, and UX ([a77033c](https://github.com/gilosorg/auth/commit/a77033c616cfc07fd5b5243480d8bfdd7bb2dca5))
* harden account re-auth flows, oauth consent reliability, and docs jwt inspector ([bc7e99d](https://github.com/gilosorg/auth/commit/bc7e99db8d012e62f6086cf33a86e279cb37357a))
* harden session expiry handling, modal accessibility, and form reliability ([4d1c71a](https://github.com/gilosorg/auth/commit/4d1c71a738d2f29031f93e0f945542d3345f684a))
* polish account console UI/UX, unify design system, and add security activity feed ([023b057](https://github.com/gilosorg/auth/commit/023b057e0a58b0e85156f56294c152c5c05654c9))
* polish consumer UI/UX, copy clarity, and flush 0px architecture ([d3ce944](https://github.com/gilosorg/auth/commit/d3ce94400d17b4474d68e11f902e84ceffa1cd47))
* protect one-time secret reveal and refine portal keyboard navigation ([ef33ef2](https://github.com/gilosorg/auth/commit/ef33ef206d3bb2f3809b74f76aa9aa5cc116bfcf))
* refine console UX, OAuth return navigation, and docs developer workflow ([748aaa0](https://github.com/gilosorg/auth/commit/748aaa04526ad48e166687f03933ba2f016716c4))
* replace legacy PHP email backend with Resend SDK ([c61c5f2](https://github.com/gilosorg/auth/commit/c61c5f2ae3b54cab1b0014e5ff0d68daa64cad26))
* replace username @ addons with Fluent UI icons, remove monospace handles, and align pagination footer bars ([d645126](https://github.com/gilosorg/auth/commit/d6451263979ecf4de99c53de220addb523a47254))
* support RFC 7009 token_type_hint, public revocation CORS, S256 PKCE enforcement and SQLite WAL auto-checkpoint ([d729e81](https://github.com/gilosorg/auth/commit/d729e816816b67e7bab1b266a879298e2c4cadbf))


### Bug Fixes

* align username prefix and refine sharp architectural UI system ([2e38772](https://github.com/gilosorg/auth/commit/2e387720bbd86e6c1d243e13e67778c87a4d4081))
* center mobile language dropdown cleanly without animation overlap ([00b1fdd](https://github.com/gilosorg/auth/commit/00b1fdd8ee8c7f6261c29b7fc59cf6d0eeec2973))
* define password toggle helpers at top scope on /home and expose contact verification flags ([2e6ef37](https://github.com/gilosorg/auth/commit/2e6ef371ad4d73975f101b5d6717cd23dbbed013))
* enforce immutable Eskiz verified SMS template across all flows ([6e057fc](https://github.com/gilosorg/auth/commit/6e057fc7824355a167694c88b231a081922289b9))
* harden auth security, TOTP encryption, OAuth 2.1 compliance and session handling ([0e8f812](https://github.com/gilosorg/auth/commit/0e8f81282567bc696d07b11e59784c7e35d11f51))
* harden OAuth 2.1 token replay revocation, session rotation, and input validation ([f339ac4](https://github.com/gilosorg/auth/commit/f339ac4c449a73367671ed5e699f22cb93d3eb93))
* harden OAuth scope normalization, TOTP attempts, session filtering, and audit logs ([76515b1](https://github.com/gilosorg/auth/commit/76515b1282968afeec1a8da78ec00b4fe5bd17fe))
* migrate transactional sender to auth.gilos.org and contact to info@gilos.org ([2a8ba0d](https://github.com/gilosorg/auth/commit/2a8ba0d3f03fe7709235d50197178305bf5e2fef))
* normalize UI geometry to rounded modern controls and soft spacing ([a9be372](https://github.com/gilosorg/auth/commit/a9be372da8f370205f732038c6afea3450c1dd57))
* place mobile responsive media rules after base styles ([d093b56](https://github.com/gilosorg/auth/commit/d093b5696404256a90766382ecdb9a87a31b38fe))
* polish UI consistency, interactive states, and OTP email layout ([7bff1ba](https://github.com/gilosorg/auth/commit/7bff1ba874b620bcd6950a92ae9cb005a5d23b54))
* polish UI controls, shared OTP interactions, and dark mode tokens ([e32b1a4](https://github.com/gilosorg/auth/commit/e32b1a40015cbae95594009a3248eee1105a2c02))
* polish UI ergonomics, theme fallbacks, and copy clarity ([a0dc7f5](https://github.com/gilosorg/auth/commit/a0dc7f5792f82a9e57fce57a6b733376e5e1d482))
* polish UI/UX, keyboard accessibility, and responsive layout ([71326c2](https://github.com/gilosorg/auth/commit/71326c2fde39a105219c3c85910ddf6e8697a4ff))
* refine keyboard focus, optional fields, and calm consumer copy ([d7b9c1d](https://github.com/gilosorg/auth/commit/d7b9c1d7cb1c79a58b422ea87ed8c4dfcf3ef78e))
* refine secondary controls, phone input, filter alignment, and card polish ([dd25f26](https://github.com/gilosorg/auth/commit/dd25f26629bed2325980c317e5463d9aa435c773))
* remove box frame around auth and oauth logos ([091c71c](https://github.com/gilosorg/auth/commit/091c71c5ddbb491676ce45935fa7b6778536143d))
* renovate UI hierarchy, hairline surfaces, and header layout ([4b77a8e](https://github.com/gilosorg/auth/commit/4b77a8ef9d90f4ca33a89b6f514841be0533d2db))
* resolve real client IP behind reverse proxy for rate limiting ([65065d3](https://github.com/gilosorg/auth/commit/65065d36a3b0e9b647c3ff7eaf1edb9bdaaacd25))
* restore corporate sharp UI geometry from dd25f26 ([b9e05ff](https://github.com/gilosorg/auth/commit/b9e05ffbd5bf63e7569ff942513aee2581c8221c))
* restore natural SVG icons and circular indicators alongside sharp containers ([46af3ae](https://github.com/gilosorg/auth/commit/46af3ae434a661dd9755b531f86f939486137576))
* use cardless mobile canvas for auth flows and refine responsiveness ([49d63ef](https://github.com/gilosorg/auth/commit/49d63efd5509625e889d44775bc72b54155159a9))

## [0.1.6](https://github.com/gilosorg/auth/compare/v0.1.5...v0.1.6) (2026-09-06)


### Bug Fixes

* session IP detection and per-access metadata updates ([6e05f91](https://github.com/gilosorg/auth/commit/6e05f91dc55f2bf50b0081d92d71275f2f581471))

## [0.1.5](https://github.com/gilosorg/auth/compare/v0.1.4...v0.1.5) (2026-09-06)


### Bug Fixes

* proper session IP detection with per-access updates ([fe897da](https://github.com/gilosorg/auth/commit/fe897da931f768c8237bb3a3a115a377d6a51e04))

## [0.1.4](https://github.com/gilosorg/auth/compare/v0.1.3...v0.1.4) (2026-09-05)


### Bug Fixes

* copyright ([32d3332](https://github.com/gilosorg/auth/commit/32d33320440eae37ef7f368938618b8d07b855d7))

## [0.1.3](https://github.com/gilosorg/auth/compare/v0.1.2...v0.1.3) (2026-08-30)


### Bug Fixes

* bugs ([cf0af5a](https://github.com/gilosorg/auth/commit/cf0af5a6a06e81ed921cf8067f78c6c39e1823a4))

## [0.1.2](https://github.com/gilosorg/auth/compare/v0.1.1...v0.1.2) (2026-08-30)


### Bug Fixes

* clean up ([4dda972](https://github.com/gilosorg/auth/commit/4dda972d605226a5b1fece95e950aa61bc3cf9c8))

## [0.1.1](https://github.com/gilosorg/auth/compare/v0.1.0...v0.1.1) (2026-08-30)


### Bug Fixes

* clean up ([130fcaf](https://github.com/gilosorg/auth/commit/130fcaf268633516cd9c7049d768809c4a8815f6))
* remove form-action from csp to unblock oauth redirects ([84548b8](https://github.com/gilosorg/auth/commit/84548b84b6e1f4745ddbd10d112b35f7482628c7))

## [0.1.0](https://github.com/gilosorg/auth/compare/v0.0.5...v0.1.0) (2026-08-29)


### Features

* inject dynamic versioning into ui ([b890ab9](https://github.com/gilosorg/auth/commit/b890ab92018dc0f7926b9fa5b8b609e00c1ece58))
* setup automated semantic versioning and release workflow ([f765ec0](https://github.com/gilosorg/auth/commit/f765ec08fbc7c45ec0b7f79bcdc54ee370075d6c))


### Bug Fixes

* add missing config import for versioning ([85575a0](https://github.com/gilosorg/auth/commit/85575a0dd4d77e895fee94e01e9aba3a4ab6079f))
* changes in some ui templates ([3db0242](https://github.com/gilosorg/auth/commit/3db02422b6ca4c2bdf3a2dc1629852c10dec0171))
* csrf token error at oauth consent screen ([960890b](https://github.com/gilosorg/auth/commit/960890bc3c1bd1fe63e279434f6a8bce7a98373c))
* fetch tags in deployment script for correct versioning ([29e30bf](https://github.com/gilosorg/auth/commit/29e30bffe658568c53d48f3f2f69779f65aca893))
* move dynamic version link to copyright footer ([141939b](https://github.com/gilosorg/auth/commit/141939ba3b0cedab83c07e21ca3a3be0e313586a))
* revert deployment to track main instead of tags for live dev ([afc19b2](https://github.com/gilosorg/auth/commit/afc19b2fb6e800e8ddfc2cf5d2d9d58b67344b7c))
* test automated release pipeline ([cb5c597](https://github.com/gilosorg/auth/commit/cb5c5971b49bfa6edb10ef7cf5f7d8fdecdb55a1))
* update docs and help links in footer ([eab5207](https://github.com/gilosorg/auth/commit/eab5207b8ff26db8fed5426bd5c3d861d94d25ae))

## [0.0.5](https://github.com/gilosorg/auth/compare/v0.0.4...v0.0.5) (2026-08-29)


### Bug Fixes

* changes in some ui templates ([3db0242](https://github.com/gilosorg/auth/commit/3db02422b6ca4c2bdf3a2dc1629852c10dec0171))
* csrf token error at oauth consent screen ([960890b](https://github.com/gilosorg/auth/commit/960890bc3c1bd1fe63e279434f6a8bce7a98373c))
* update docs and help links in footer ([eab5207](https://github.com/gilosorg/auth/commit/eab5207b8ff26db8fed5426bd5c3d861d94d25ae))

## [0.0.4](https://github.com/gilosorg/auth/compare/v0.0.3...v0.0.4) (2026-08-28)


### Bug Fixes

* fetch tags in deployment script for correct versioning ([29e30bf](https://github.com/gilosorg/auth/commit/29e30bffe658568c53d48f3f2f69779f65aca893))

## [0.0.3](https://github.com/gilosorg/auth/compare/v0.0.2...v0.0.3) (2026-08-28)


### Bug Fixes

* move dynamic version link to copyright footer ([141939b](https://github.com/gilosorg/auth/commit/141939ba3b0cedab83c07e21ca3a3be0e313586a))
* test automated release pipeline ([cb5c597](https://github.com/gilosorg/auth/commit/cb5c5971b49bfa6edb10ef7cf5f7d8fdecdb55a1))
