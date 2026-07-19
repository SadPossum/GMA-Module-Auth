# TOTP Authenticator Lifecycle And Recovery Task

Status: completed

## Purpose

Add production-grade, optional time-based one-time password (TOTP) verification to Auth without making Framework understand a particular authenticator, bloating the `Member` aggregate, or allowing a second-factor bypass through password recovery or external sign-in.

This slice follows the project boundaries:

- Framework keeps only provider-neutral authentication-assurance claims and enforcement mechanics. It receives no TOTP, QR, recovery-code, or MFA lifecycle code.
- Auth owns authenticator state, login enforcement, one-time challenges, recovery codes, session issuance, security events, and persistence.
- `Gma.Modules.Auth.Authenticators.Totp` owns the optional RFC 6238 implementation, provisioning URI construction, random TOTP secret generation, and the default protected-secret adapter.
- A host may replace the TOTP or secret-protection ports with another standards-compliant implementation, KMS, or HSM integration.
- Extensions remain reserved for cross-module reactions such as Notifications delivery. No extension owns or reads Auth credential tables.
- Products consume Auth contracts and choose which operations require Auth assurance contexts. BunkFy-specific roles, screens, and protected actions stay outside GMA.

## Standards Baseline

- RFC 6238 requires a unique random secret per authenticator, protected secret storage, a default 30-second time step, bounded clock tolerance, and rejection of a TOTP value already accepted in the same time step.
- RFC 8176 defines `pwd`, `otp`, and `mfa` authentication method references, while keeping authentication context (`acr`) distinct from method evidence (`amr`).
- NIST SP 800-63B treats a typical authenticator-app TOTP as a single-factor OTP authenticator proving possession. Password plus TOTP is therefore a multi-factor event; an unknown external-provider method plus local TOTP is only safely described as a two-step event unless the provider adapter contributes validated factor evidence.
- NIST recovery codes are one-time lookup secrets: deliver them through an authenticated channel, store only verifier-safe representations, accept each once, and rate-limit attempts.

GMA does not claim a NIST AAL from the presence of `otp`, `mfa`, or a configured authenticator. Deployment controls, authenticator implementation, secret custody, recovery policy, and product risk policy remain part of the assurance decision.

## Domain Ownership

### Member authenticator aggregate

Create a separate scoped `MemberTotpAuthenticator` aggregate rather than adding TOTP state to `Member`. The aggregate owns:

- one authenticator identity and owning member;
- pending versus active lifecycle state;
- protected secret ciphertext, never plaintext;
- enrollment creation and expiration times;
- activation, disablement, and recovery-code regeneration times;
- the last accepted TOTP time step to prevent replay;
- bounded recovery-code entities containing only keyed hashes and consumed timestamps;
- an optimistic-concurrency token.

The first slice supports at most one active or pending TOTP authenticator per member. Persistence enforces that invariant with a scope/member unique key. Replacing an authenticator requires disabling the active authenticator first so recovery and audit semantics remain unambiguous.

### Primary-authentication challenge aggregate

Create a separate scoped `MemberAuthenticationChallenge` aggregate for the gap between a valid primary credential and an issued session. It owns:

- a high-entropy, single-use challenge-token hash;
- the member and scope;
- the normalized primary authentication method;
- conservative primary authentication evidence and its timestamp;
- bounded client IP and user-agent context;
- creation and expiration times;
- failed-attempt count and maximum-attempt state;
- consumed or revoked state;
- an optimistic-concurrency token.

No access token, refresh token, or authenticated browser cookie exists until the challenge is completed. Creating a new primary challenge revokes prior active challenges for that member. Challenge tokens and recovery codes never enter events, logs, URLs, metrics, or durable client storage controlled by Auth.

## Assurance Semantics

Add Auth-owned context and method references without changing Framework:

| Authentication event | Context | Methods |
| --- | --- | --- |
| Password only | `urn:gma:acr:password` | `pwd` |
| Validated external sign-in only | `urn:gma:acr:external` | private external marker |
| Password plus TOTP | `urn:gma:acr:mfa` | `pwd`, `otp`, `mfa` |
| Password plus recovery code | `urn:gma:acr:mfa` | `pwd`, private recovery marker, `mfa` |
| External sign-in plus TOTP | `urn:gma:acr:two-step` | private external marker, `otp` |
| External sign-in plus recovery code | `urn:gma:acr:two-step` | private external marker, private recovery marker |

Product authorization must depend on accepted contexts and freshness, not compare method names or assume a global strength ranking. Provider adapters may contribute richer evidence in a later slice only after validating the upstream assertion and its semantics.

## User Flows

### Enrollment

1. An authenticated member begins enrollment from an active, recently authenticated password or external session.
2. Auth invalidates an older pending enrollment, asks the TOTP adapter for a random secret, protects it immediately, and persists only ciphertext.
3. Auth returns the Base32 secret and `otpauth://` provisioning URI once with `Cache-Control: no-store`. QR rendering belongs to the client.
4. The member activates enrollment by submitting a TOTP code and the exact active session refresh proof.
5. Auth verifies the code, atomically records the accepted time step, activates the authenticator, rotates the current refresh token, and upgrades the session evidence.
6. Auth generates high-entropy recovery codes, persists only keyed hashes, and returns plaintext codes once in the activation response.
7. Auth publishes an authentication-method-added event for `totp`; secrets and codes are excluded.

An authenticator is never advertised as active before code verification and enforcement are both available. Pending enrollment expires and is removed by retention.

### Password sign-in

1. Auth validates the username, password, member state, scope, and first-factor rate limit exactly as it does today.
2. If no active authenticator exists, Auth creates the session and returns the existing `200 AuthTokensResponse`.
3. If an active authenticator exists, Auth creates a one-time primary challenge and returns `202 MfaChallengeResponse`; no session is created.
4. The client completes the challenge with a TOTP or recovery code.
5. Auth verifies challenge state and rate limits, consumes the factor atomically, creates the session with combined evidence, consumes the challenge, and returns tokens.

The existing successful `200` login contract remains unchanged. The `202` response is additive.

### External sign-in

Every external sign-in follows the same enforcement decision after the provider exchange is validated. An active local authenticator produces a primary challenge instead of tokens, preventing external login from bypassing TOTP. The external exchange response adds an `mfa-required` status and challenge metadata; browser transport maps this to the same `202 MfaChallengeResponse` used by password login.

New external members may be created before the challenge completes, but they receive no session. Provider tokens remain unstored, and replay of the external exchange code remains impossible.

### Recovery codes

- Generate a bounded set of high-entropy codes during activation and regeneration.
- Normalize presentation separators and case before hashing, while retaining enough entropy that fast keyed verification is appropriate.
- Check candidate hashes in constant time and consume the matching code in the authenticator aggregate.
- Never return remaining plaintext codes after their one-time delivery.
- Expose only the remaining unused count in self-service and admin read models.
- Regeneration invalidates every old code and requires a fresh successful TOTP or recovery-code proof plus current session refresh proof.

### Disablement and administrative recovery

Self-service disablement requires a fresh successful TOTP or recovery-code proof and current session refresh proof. It disables the authenticator, invalidates recovery codes and outstanding primary challenges, records the method removal, and revokes all member sessions. The member signs in again using a remaining primary method.

Password recovery changes only the password and continues to revoke sessions; it must not silently disable TOTP. A member who loses both the authenticator and all recovery codes needs an explicit administrative recovery path.

Add a separate `auth.members.reset-multi-factor` administration permission and confirmed API/CLI operation. Administrative reset requires a bounded reason, disables the authenticator, invalidates recovery codes and challenges, revokes all sessions, and publishes security events. It never reveals or replaces a secret on the member's behalf. Product identity-verification policy before granting this operation remains outside Auth.

## API Surface

Bearer routes use refresh proof in the request. Browser routes use the existing HttpOnly refresh cookie and never expose refresh tokens to JavaScript.

| Method | Route | Result |
| --- | --- | --- |
| `GET` | `/api/auth/mfa` | Active/pending state, recovery-code count, and lifecycle timestamps. |
| `POST` | `/api/auth/mfa/totp/enrollment` | Begin or replace an expired pending enrollment. |
| `POST` | `/api/auth/mfa/totp/activate` | Activate, rotate the session, and return tokens plus recovery codes once. |
| `POST` | `/api/auth/mfa/challenges/complete` | Complete a password or external primary challenge with TOTP or recovery code. |
| `POST` | `/api/auth/mfa/recovery-codes/regenerate` | Replace all recovery codes after fresh factor proof. |
| `POST` | `/api/auth/mfa/totp/disable` | Disable after fresh factor proof and revoke sessions. |

Equivalent browser routes live under `/api/auth/browser/mfa`. Public responses use one generic invalid-factor/challenge error so callers cannot distinguish expired challenges, exhausted attempts, unknown members, stale codes, consumed codes, or TOTP replay.

All secret-bearing responses set `Cache-Control: no-store` and `Pragma: no-cache`. OpenAPI marks secret, code, challenge-token, and recovery-code fields as write-only or sensitive where supported.

## Adapter Ports

Application defines narrow ports:

- `ITimeBasedOneTimePasswordProvider` creates a secret, builds a provisioning URI, and verifies a code at an explicit UTC time while returning the matched time step.
- `IAuthenticatorSecretProtector` protects and unprotects TOTP secret bytes.
- `IMultiFactorTokenService` generates and hashes high-entropy primary-challenge and recovery-code material with active/previous key support.

`Gma.Modules.Auth.Authenticators.Totp` provides the default implementation using Otp.NET for RFC 6238 and ASP.NET Core Data Protection for secret protection. The adapter replaces Auth's unavailable fail-closed defaults; a host can register a KMS/HSM-backed protector or another validated implementation after the adapter.

The adapter uses:

- a cryptographically random secret of at least 160 bits;
- SHA-1, six digits, and a 30-second period for broad authenticator-app interoperability;
- the current and immediately previous time step only;
- the persisted matched time step to enforce one-time use.

Data Protection key rings must be persisted, encrypted where the platform supports it, shared across replicas, and configured with a stable application name. Losing the key ring makes protected TOTP secrets unusable. The adapter documentation must make this deployment invariant explicit and must not ship an ephemeral production default disguised as durable storage.

## Persistence And Retention

Auth adds provider-specific PostgreSQL and SQL Server migrations for:

- `member_totp_authenticators`;
- `member_totp_recovery_codes`;
- `member_authentication_challenges`;
- `member_multi_factor_failure_attempts`;
- unique scope/member ownership;
- challenge-token and recovery-code hash lookup indexes;
- active/expiry cleanup indexes;
- concurrency tokens and bounded columns.

No migration enables TOTP for an existing account or infers stronger evidence for an existing session. Existing accounts and sessions retain current behavior until a member activates an authenticator.

Retention deletes expired/consumed challenges, expired pending enrollments, old disabled authenticator history, and old management-factor failure records in bounded batches. Active authenticator and unused recovery-code state is never removed by age alone.

## Security Invariants

- An active authenticator is enforced for every password and external sign-in path.
- No session exists between primary and second-factor verification.
- TOTP secrets are plaintext only inside the adapter for the shortest practical period.
- A TOTP time step is accepted at most once per authenticator, including concurrent requests.
- A recovery code is accepted at most once and all previous codes become invalid on regeneration or disablement.
- Challenge and factor attempts are rate-limited durably; edge/IP rate limiting remains required.
- Challenge success, session creation, factor consumption, and challenge consumption commit atomically.
- Optimistic-concurrency conflicts fail closed and never mint duplicate sessions.
- Password reset does not remove MFA. Administrative reset is explicit, permissioned, confirmed, reasoned, audited, and session-revoking.
- TOTP is not described as phishing-resistant.
- Raw secrets, TOTP values, recovery codes, challenge tokens, protected ciphertext, and token hashes never enter events or logs.

## Verification

- RFC 6238 test vectors and adapter tests cover secret encoding, provisioning URI escaping, current/prior windows, malformed codes, clock boundaries, and matched-step reporting.
- Domain tests cover lifecycle transitions, expiration, replay rejection, recovery-code one-time use, regeneration, disablement, attempt exhaustion, and invalid state transitions.
- Application tests prove password and every external path cannot bypass an active authenticator.
- Tests prove no session or token is issued before factor completion and combined evidence is truthful for password versus external primary methods.
- Concurrency tests prove duplicate TOTP/recovery/challenge consumption fails closed.
- Browser tests prove secret material never enters refresh cookies or URLs and that successful completion uses existing cookie transport.
- Password recovery tests prove MFA remains active; admin recovery tests prove explicit permission, confirmation, reason, event, and session revocation.
- PostgreSQL and SQL Server migration drift checks, idempotent scripts, indexes, constraints, and model parity pass.
- Architecture tests keep the adapter optional, Domain/Application free of ASP.NET and Otp.NET, and Framework free of Auth dependencies.
- Skeleton composes the adapter explicitly, documents durable Data Protection keys, and updates canonical project/solution guards.
- BunkFy updates only published submodule revisions and generated contracts before product UI work begins.

## Non-Goals

This slice does not add:

- SMS or email OTP;
- passkeys/WebAuthn;
- remembered or trusted devices;
- multiple simultaneous TOTP authenticators;
- provider-specific upstream MFA prompting or upstream `amr` translation;
- backup-code delivery by email or Notifications;
- product identity-proofing for administrative recovery;
- BunkFy-specific role policy, screens, or high-risk operation choices;
- NIST AAL certification.

## Completion Criteria

- A member can enroll, activate, inspect, use, recover, regenerate, and disable TOTP safely.
- Every primary sign-in path enforces an active authenticator before session issuance.
- Recovery and concurrency behavior cannot reuse a code, bypass the factor, or silently weaken account security.
- The optional adapter can be replaced without changing Auth domain/application behavior.
- Framework remains unchanged and dependency-neutral.
- Auth, both database providers, Skeleton, and BunkFy verification lanes pass from published dependency revisions.

## Completion Record

The optional TOTP adapter, Auth-owned lifecycle and recovery model, PostgreSQL and SQL Server migrations, public/browser flows, administrative reset surfaces, retention, replay and concurrency controls, canonical Skeleton composition, and BunkFy consumer alignment are implemented. Auth and Skeleton CI pass on their published revisions; BunkFy passes its warning-free full build, migration drift matrix, non-Docker suites, 32 required Docker integration scenarios, generated-contract drift check, and frontend verification.
