# Account Recovery Task

Status: in progress
Date: 2026-07-19

## Goal

Add production-oriented password account recovery to Auth without turning the `Member` aggregate into a collection of unrelated security workflows. Recovery must preserve Auth ownership of credentials and sessions, remain usable in both global and scope-aware profiles, and compose with delivery through public integration events.

This task does not add MFA, passkeys, product profile data, workspace membership, authorization policy, or a product-specific recovery UI.

## Domain Boundary

Account recovery is an optional Auth capability, not a separate business module. Password mutation and session revocation are Auth invariants and must complete in the same Auth unit of work. The recovery challenge is a separate scoped aggregate with its own repository, persistence model, lifecycle, and retention; `Member` only performs its existing password-reset and session-revocation behavior during confirmation.

Auth publishes a transport-neutral recovery-requested event. Email delivery belongs in `Gma.Extensions.Auth.Notifications`, keeping Auth independent of Notifications and provider SDKs.

## Public Contract

- `POST /api/auth/password-recovery` accepts an email address and always returns `202 Accepted` for a structurally valid request, whether or not an eligible account exists.
- `POST /api/auth/password-recovery/confirm` accepts a high-entropy one-time code and new password. Success returns `204 No Content`. The event also carries a challenge id for product-specific link templates and audit correlation, but confirmation does not require clients to submit two secrets from the same delivery.
- unknown, expired, consumed, revoked, wrong-scope, and replayed challenges share one public invalid-recovery error;
- confirmation never signs the member in or returns tokens; the member must authenticate again after all existing sessions are revoked.

Scope-aware hosts require the active scope on both endpoints. Global Auth always uses its configured fixed scope.

## Challenge Lifecycle

- generate a high-entropy opaque code and store only its rotating HMAC hash;
- bind each challenge to the exact Auth scope, member, and active verified email used for delivery;
- require an active member with a configured password and verified active email before publishing a delivery event;
- revoke older active challenges when a new eligible request is accepted;
- enforce a durable account-level request cooldown, with edge/IP limiting still required by the host;
- expire challenges after a bounded configured lifetime;
- consume a challenge exactly once and invalidate every other challenge for the member during successful confirmation;
- use optimistic concurrency so competing confirmations cannot both change credentials;
- retain no provider token and never put recovery secrets in logs, URLs, web notifications, or error details.

The raw code exists only in the bounded delivery path: the Auth domain event/outbox and any explicitly installed notification or email inbox/outbox records needed to complete delivery. It is never stored on the recovery challenge, exposed to unrelated channels, or written to logs. Every delivery-path store containing the code must be encrypted at rest and retained according to the host's security policy.

## Required Changes

### Auth repository

- add recovery API request contracts, transactional commands, validators, handlers, and public error mapping;
- add a scoped `PasswordRecoveryChallenge` aggregate and repository without adding recovery state to `Member`;
- add a semantic recovery-token service backed by the existing rotating secret-hashing infrastructure;
- add `MemberPasswordRecoveryRequestedIntegrationEvent` and metadata/subject declarations;
- persist challenges in the Auth schema with lookup, member, expiry, and concurrency indexes;
- extend bounded Auth retention to remove expired and completed recovery challenges;
- add SQL Server and PostgreSQL migrations and verify model drift;
- document configuration, security invariants, and operational requirements.

### GMA Extensions repository

- map the recovery-requested event to a mandatory email-only notification addressed to the event's exact verified email;
- include the challenge id, recovery code, and expiry only in the delivery payload;
- add extension registration and projection tests;
- do not create a web notification containing the recovery secret.

### GMA Skeleton

- update Auth and Extensions source pins only after both repositories pass focused verification;
- prove composition with Auth, Notifications, the extension, and an email adapter;
- keep reusable recovery behavior out of Skeleton.

## Security Invariants

- the request response cannot reveal account existence, status, password presence, or email verification state;
- a challenge cannot cross Auth scopes or be redirected to a different address;
- only an active member with an existing password can recover that password;
- a successful confirmation consumes the challenge, changes the password, revokes all sessions, and emits existing authentication-method/session security events atomically;
- replay, expiry, revocation, and invalid codes fail identically;
- password policy and compromised-password checks apply to recovery exactly as they do to authenticated/admin password changes;
- pepper rotation accepts active and configured previous peppers while new challenges use the active pepper;
- concurrent confirmation is fail closed;
- extension absence affects delivery only, never Auth state ownership or module composition.

## Verification

- domain tests cover creation, cooldown, rotation, expiry, revocation, consumption, and invalid state transitions;
- application tests cover eligible and ineligible requests, generic enumeration-safe responses, password policy, replay, scope isolation, session revocation, and security events;
- persistence tests cover candidate-hash lookup, query filtering, model indexes, and fail-closed optimistic concurrency; retention cleanup is provider-backed and verified through both generated migration models;
- API contract tests cover anonymous routes, scope requirements, response codes, and request validation;
- integration-event contract tests cover normalization, versioning, and module metadata;
- Extensions tests prove mandatory email-only routing to the exact event address;
- SQL Server and PostgreSQL have no pending model changes after migrations;
- focused tests, solution builds, package vulnerability audit, architecture guards, and `git diff --check` pass in every changed repository.

## Deferred Auth Capabilities

MFA, passkeys, recovery codes for MFA, authentication assurance, and step-up policy remain unopened. Their design follows this same rule: independent capability state and adapters built on Auth identity/session/event seams, with only the smallest credential invariant kept inside `Member`.

## Completion Criterion

The slice is complete when an eligible member can request and complete a one-time password recovery in either Auth profile without account enumeration or cross-scope access, every prior session and recovery challenge is invalidated atomically, optional email delivery composes through GMA Extensions, both provider migrations are clean, and the repositories plus Skeleton pass their focused proof.
