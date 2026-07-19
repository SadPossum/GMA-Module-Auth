# Auth Production Hardening Task

Status: complete
Date: 2026-07-19

## Goal

Close the remaining security, bounded-state, maintainability, and standalone-verification gaps in the reusable Auth domain without moving product authorization, organization membership, staff profiles, notification delivery, provider UI, or BunkFy policy into Auth.

The existing global/scope-aware identity model, password and external identities, email verification, password recovery, authentication assurance, TOTP lifecycle, sessions, administration surfaces, and integration events remain the foundation.

## Audit Baseline

- the zero-warning solution build and all 221 focused tests pass;
- SQL Server and PostgreSQL have no pending Auth model changes;
- the direct and transitive package audit reports no known vulnerabilities;
- Auth source does not reference another reusable module or product source;
- Framework owns only provider-neutral assurance claims and ASP.NET Core enforcement, while Auth owns credentials, sessions, authenticator state, and security events;
- `Gma.Extensions.Auth.Notifications` remains the optional cross-module delivery bridge;
- Skeleton and BunkFy already consume the published recovery, assurance, and TOTP revisions.

## Findings

1. `IAuthenticationAttemptLimiter` defaults to process-local memory. Multi-replica password login and password step-up therefore do not share account throttling, and authenticated password-proof operations such as password removal or provider unlinking have no account-level limiter.
2. Unknown and ineligible password login paths skip password-hash verification, leaving a measurable timing difference even though the public error is generic.
3. Auth loads every historical session into the `Member` aggregate on common reads. Retention is intentionally opt-in, so long-running installations can make login, refresh, and account reads grow with total session history.
4. Expired sessions remain `IsActive` until cleanup and are currently returned by the self-service session list. Successful primary authentication also has no configurable active-session ceiling.
5. Refresh tokens, external exchange codes, email-verification codes, password-recovery codes, MFA challenge tokens, and MFA recovery codes reuse one keyed-hash input domain. Tables are separate, but new secrets should be cryptographically purpose-separated while retaining compatibility with existing hashes and pepper rotation.
6. Auth responses are not uniformly marked `no-store` and `no-cache`; authenticated methods/session/MFA reads and some failed secret-bearing operations can inherit cacheable defaults.
7. The 1,100-line public API module mixes composition, four endpoint families, browser cookie transport, response policy, and claim parsing. This makes security review and additive adapter work harder than necessary.
8. Auth CI lacks the standalone boundary, provider migration-drift, vulnerability, and real PostgreSQL integration gates used by the current reusable-module standard.
9. The assurance task is implemented and pinned downstream but still lacks an explicit cross-composition acceptance proof and completion record.

## Delivery Slices

### 1. Durable Credential Attempt Limiting

- make password-attempt limiting asynchronous and persistence-backed by default when the complete Auth module is composed;
- retain the in-memory implementation only as an application-only fallback and explicit replacement seam;
- persist only purpose-separated keyed target hashes, bounded purpose names, timestamps, and scope; never persist attempted passwords or raw usernames;
- cover unknown usernames, password login, password step-up, password change/removal, and external-identity unlink proof;
- use the existing failure-window and limit options, perform failure writes independently of failed command transactions, and remove matching failure history after successful proof;
- add bounded retention and provider indexes for attempt history;
- keep edge/IP limiting as a separate deployment control.

### 2. Bounded Session Working Set

- load only unexpired active sessions on aggregate command paths while preserving refresh replay protection for usable sessions;
- make self-service session discovery exclude expired sessions even before retention runs;
- replace admin read-path collection hydration with server-side bounded projections/counts;
- add a validated `MaximumActiveSessionsPerMember` option and revoke the oldest active sessions when a successful primary authentication exceeds the configured ceiling;
- apply the same ceiling to password, external, and MFA-completed session creation;
- keep historical session retention opt-in and independent from the hot aggregate working set.

### 3. Secret And HTTP Response Hardening

- domain-separate newly written hashes for external exchange, email verification, password recovery, MFA challenge, and MFA recovery tokens;
- accept legacy unscoped keyed hashes during the existing pepper-rotation window so deployment does not invalidate in-flight secrets;
- perform a dummy password verification on unknown/ineligible login paths and preserve generic credential errors;
- apply `Cache-Control: no-store` and `Pragma: no-cache` to every Auth endpoint response, including failures, authenticated reads, browser flows, provider callbacks, and disabled-adapter discovery;
- keep secrets out of routes, logs, metrics, exceptions, and non-delivery events.

### 4. API And Aggregate Reviewability

- reduce `AuthModule` to composition and route-group orchestration;
- split public identity, account security, MFA, and browser-cookie endpoint mapping into cohesive internal files;
- centralize claim parsing, scope matching, browser-cookie policy, public error mapping, and secret-response handling;
- preserve every route and wire contract exactly;
- keep `Member` as the credential/session consistency boundary for this slice; do not move sessions into a separate aggregate unless the bounded working-set proof shows that the existing invariant cannot remain efficient.

### 5. Standalone And Downstream Proof

- add Auth-owned boundary and migration-drift scripts plus vulnerability auditing to CI;
- add real PostgreSQL integration proof for durable throttling, session filtering/ceiling, concurrency, and bounded retention;
- keep SQL Server and PostgreSQL migration models and idempotent scripts aligned;
- add a Skeleton test-only endpoint proof that an actual Auth token satisfies or fails Framework assurance requirements without selecting product policy;
- update the assurance task to completed only after exact Auth, Framework, Skeleton, and BunkFy dependency revisions pass;
- align generated source-first configuration and BunkFy pins/configuration without adding BunkFy roles or protected-operation choices to GMA.

## Ownership Boundaries

Auth continues to own:

- member credentials and external identity links;
- email ownership state and recovery challenges;
- sessions, refresh replay response, authenticator lifecycle, credential attempt history, and Auth retention;
- trusted authentication evidence and security events.

Framework continues to own:

- provider-neutral `acr`, `amr`, and `auth_time` vocabulary;
- provider-neutral assurance requirements and the optional ASP.NET Core challenge adapter;
- generic bounded-batch and persistence composition primitives.

GMA Extensions continues to own:

- Auth-to-Notifications delivery reactions;
- Auth-to-Organizations admission integration.

Products continue to own:

- which operations require recent or stronger authentication;
- registration confirmation fields and account-security UI;
- organization roles, permissions, staff data, onboarding, and identity-proofing policy;
- edge rate limiting, secret custody, Data Protection storage, email transport, and deployment monitoring.

No Framework implementation change is planned. The existing generic assurance, bounded-batch, CQRS, and persistence primitives are sufficient.

## Acceptance Criteria

- password proof is account-throttled consistently across replicas and every applicable Auth path;
- unknown login work is timing-hardened and all public credential errors remain generic;
- aggregate command reads do not hydrate historical/expired sessions, expired sessions do not appear active, and active sessions stay within a configured ceiling;
- newly generated one-time secrets use purpose-separated hashes while compatible in-flight legacy secrets still validate;
- every Auth response is non-cacheable and secret-bearing responses retain their existing contracts;
- route and OpenAPI contracts do not drift during API decomposition;
- Auth boundary, zero-warning build, focused tests, both provider migration checks, vulnerability audit, and PostgreSQL integration tests pass;
- Framework remains dependency-neutral and unchanged unless the audit proves a genuinely generic missing primitive;
- Skeleton provides the canonical assurance composition proof and BunkFy passes backend/web contract verification from published revisions.

## Implementation Checkpoint

The Auth-owned implementation and downstream proof are complete:

- durable keyed credential-failure history is the default for complete Auth composition, with bounded-retention support and both provider migrations;
- password proof performs uniform work across login, step-up, password change/removal, and external unlink; durable attempt partitioning also covers MFA management factors;
- active session hydration and discovery are bounded, and primary authentication enforces `MaximumActiveSessionsPerMember`;
- one-time token hashes are purpose-separated with legacy candidate compatibility;
- the Auth API pipeline applies non-cacheable response headers to native, browser, contributed, short-circuited, malformed, and missing-route responses;
- the public API module is split into composition, core, MFA, browser, and shared support partials without route drift;
- Auth now owns boundary, migration-drift, package-audit, non-Docker, and required PostgreSQL CI lanes;
- the zero-warning build, 231 focused tests, both migration-drift checks, vulnerability audit, and cross-replica PostgreSQL limiter proof pass locally.

## Completion Record

Completed on 2026-07-19 from these exact published implementation and consumer revisions:

- Framework `c62d4ee384edb65cfb3b55f820331e72e718d802` remained dependency-neutral and unchanged;
- Auth implementation `e8f82b6ed5df7a33ad64dbc66106ea51128ca078` contains the production hardening and public-enum boundary correction;
- Skeleton `5e0bc03112a5c1a1c8e696854656277177eafe07` pins that Auth revision and proves password and MFA assurance with real Auth-issued tokens;
- BunkFy backend `f74aac7336e37607508b68b922fb9e497a908d4b` pins that Auth revision, exposes bounded host defaults, and guards them architecturally;
- BunkFy root `ab5475859ae7dabb716426f7dcc07ce50e7f0a02` pins the aligned backend and synchronizes the product workspace solution.

Required remote validation passed:

- Auth run `29692050521`: Windows validation and required PostgreSQL integration passed;
- Skeleton run `29692240889`: Windows and Ubuntu validation passed;
- BunkFy backend run `29692907605`: Windows and Ubuntu validation passed;
- BunkFy root run `29693351198`: backend verification, OpenAPI/web contract checks, frontend typecheck, lint, tests, and build passed.

The completion-record commit is documentation-only. Consumers will pin it after publication so strict submodule `dev`-head guards continue to hold without changing the validated implementation revision.

## Explicitly Deferred

- passkeys/WebAuthn, trusted devices, SMS/email OTP, and multiple simultaneous TOTP authenticators;
- product-specific email confirmation enforcement or mandatory MFA enrollment;
- global inactivity and absolute session lifetime policy beyond refresh expiry;
- product identity verification before administrative credential or MFA recovery;
- BunkFy-specific role policy, staff onboarding, UI, or high-risk-operation mapping;
- legal erasure and security-event archival policy beyond the bounded technical retention controls.

## Completion Criterion

The slice is complete only when Auth's credential proof and session working set remain secure and bounded across replicas, sensitive responses and secret hashes are hardened without contract breakage, the standalone module owns production-grade provider gates, the API is reviewable, and exact published Framework, Auth, Skeleton, and BunkFy revisions pass their required validation lanes.
