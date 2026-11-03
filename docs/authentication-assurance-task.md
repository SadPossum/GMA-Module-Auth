# Authentication Assurance And Step-Up Task

Status: implementation complete; downstream composition alignment follows dependency publication

## Purpose

Add a reusable authentication-assurance and step-up foundation without coupling product modules to Auth implementation details or treating specific authentication methods as a universal strength hierarchy.

This slice follows the project boundaries:

- Framework owns provider-neutral claim vocabulary and optional ASP.NET Core enforcement mechanics.
- Auth owns trusted authentication events, session evidence, password reauthentication, token issuance, and persistence.
- Provider adapters validate provider assertions before they contribute authentication evidence.
- Product modules choose which authentication contexts and freshness windows protect their operations.
- Extensions remain the place for future cross-module MFA or passkey orchestration.

## Standards Baseline

The implementation follows these protocol semantics:

- RFC 9470 uses `acr` and `auth_time` to communicate authentication context and recentness, and returns `insufficient_user_authentication` when a protected resource requires step-up.
- OpenID Connect defines `acr`, `amr`, and `auth_time` as distinct evidence. An authentication context describes rules satisfied by an event; methods describe how the event happened.
- RFC 8176 warns that authorization tied directly to specific methods becomes brittle. Product policy therefore accepts context references rather than comparing methods through a global ranking.
- NIST SP 800-63B requires a session to inherit no more assurance than its authentication event and treats successful reauthentication as a new authentication event.

GMA does not claim NIST AAL compliance from a method name alone. Deployment controls, authenticator properties, verifier behavior, and product risk policy determine whether an AAL is actually met.

## Scope

### Framework

- Add stable `acr`, `amr`, and `auth_time` claim names to the dependency-neutral security package.
- Add a provider-neutral authentication-assurance requirement with:
  - zero or more accepted authentication context references;
  - an optional maximum authentication age.
- Add an optional ASP.NET Core adapter that:
  - reads only authenticated principal claims;
  - rejects missing, malformed, or insufficient evidence;
  - returns HTTP 401 with the RFC 9470 `insufficient_user_authentication` challenge;
  - exposes endpoint-builder helpers without depending on GMA Auth.

### Auth

- Persist the authentication context, method references, and authentication time that established the current session evidence.
- Preserve that evidence when an access token is refreshed. Refreshing a token is not a new authentication event.
- Issue `acr`, `amr`, and `auth_time` claims in access tokens.
- Add password step-up endpoints for bearer-token and browser-cookie clients.
- Verify the current member, active session, refresh token, password, scope, and rate limit before step-up succeeds.
- Rotate the refresh token during step-up and retain existing refresh-token replay protection.
- Return a new access token derived only from persisted session evidence.
- Use the latest authentication time, not session creation time, for existing fresh-authentication checks.
- Record a distinct session-reauthenticated event instead of reporting step-up as a new sign-in.

## Threat Boundaries

- Clients never submit trusted `acr`, `amr`, or `auth_time` values.
- OIDC and future factor adapters must validate upstream proof before translating it into Auth evidence.
- A refresh operation must not reset `auth_time`.
- Step-up must rotate the refresh token. Otherwise, a refresh token stolen before step-up could mint a token carrying the victim's stronger evidence afterward.
- Old low-assurance access tokens remain low assurance and fail protected-resource checks.
- Authentication context references are opaque, bounded, case-sensitive values. Framework does not rank them.
- Method references are evidence and diagnostics, not authorization policy.
- Existing sessions receive conservative backfilled contexts. Migration must not infer stronger assurance than the recorded method proves.
- Password, refresh-token, and token-hash values never enter events, logs, metrics, or challenge responses.

## Non-Goals

This slice does not add:

- TOTP, SMS, email OTP, recovery codes, or MFA enrollment;
- passkeys or WebAuthn ceremonies;
- provider-specific OIDC step-up prompts;
- NIST AAL certification or a product-wide risk policy;
- authorization permissions or workspace roles;
- BunkFy-specific protected-operation choices or UI;
- global inactivity and overall session-timeout policy.

Those capabilities build on this foundation in later Auth slices.

## Verification

- Framework unit tests cover requirement validation, claim evaluation, malformed/future timestamps, accepted contexts, freshness, and RFC 9470 challenge shape.
- Auth domain tests cover initial evidence, reauthentication, inactive sessions, refresh rotation, and event behavior.
- Auth application tests cover invalid passwords, missing passwords, rate limiting, replayed refresh tokens, scope isolation, password rehash, and successful step-up.
- JWT tests prove claim round-tripping and that refresh preserves persisted evidence.
- PostgreSQL and SQL Server migration checks remain clean and idempotent scripts generate successfully.
- Architecture tests keep Framework core dependency-neutral and the ASP.NET adapter isolated.
- Skeleton and BunkFy consume only published Framework/Auth revisions and generated API contracts.

## Completion Criteria

- The Framework enforcement package can protect an endpoint with context and/or freshness requirements without referencing Auth.
- Auth can establish and refresh conservative session evidence and perform password reauthentication safely.
- No access token can gain stronger or fresher evidence merely through refresh.
- The full Auth, Framework, Skeleton, and consumer verification lanes pass.
- Follow-up MFA/passkey work can supply validated evidence without changing the core assurance model.

## Multi-Factor Session Step-Up Follow-Up

The later TOTP lifecycle slice adds an explicit recovery path for product policies that require recent `urn:gma:acr:mfa`:

- bearer and browser clients can reauthenticate the exact current session through `/api/auth/step-up/mfa`;
- the command requires the current refresh generation, current password, and a TOTP or one-time recovery code in one transaction;
- password and factor attempts use distinct rate-limit partitions, and invalid factor attempts use a distinct durable step-up history partition;
- refresh-token replay is detected before a one-time factor is consumed and retains all-session revocation;
- successful completion rotates refresh material, resets the absolute session bound, and records password-plus-factor evidence at the completion time;
- factor-only authenticator management preserves prior `acr`, `amr`, `auth_time`, and absolute session expiry;
- external-only accounts fail explicitly until a provider adapter implements and validates provider-specific reauthentication.

Product modules still choose accepted contexts and freshness windows. Auth supplies trustworthy evidence and a usable password-backed recovery ceremony; it does not activate a product-wide privileged-operation policy.
