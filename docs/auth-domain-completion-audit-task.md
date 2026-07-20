# Auth Domain Completion Audit Task

Status: in progress (reopened by exact-head consumer verification)
Date: 2026-07-19
Updated: 2026-07-20

## Goal

Verify that Auth is production-grade as a reusable identity and authentication domain, reconcile its completed task records with the current source, and close any proven gaps without moving product policy, organization membership, notifications, or provider-specific behavior into the module core.

## Ownership Boundary

- Framework owns dependency-neutral security vocabulary, assurance requirements, cryptographic and request-pipeline primitives that are useful without Auth, and optional ASP.NET Core enforcement adapters.
- Auth owns members, credentials, external-identity links, authentication events, sessions, refresh-token rotation and replay response, recovery and verification state, security events, persistence, and its public/admin contracts.
- Authenticator and identity-provider projects own protocol-specific validation and translation, such as TOTP and OpenID Connect, behind Auth-owned extension points.
- Extensions own reusable reactions or workflows that understand Auth plus another module, including Notifications and Organizations bridges.
- Products own registration UX, confirmation fields, mandatory verification or MFA policy, high-risk-operation mapping, roles, staff onboarding, identity proofing, deployment secrets, and enabled provider choices.

## Audit Slices

1. Reconcile every Auth task record and completion claim with the current `dev` source, migrations, tests, CI, Skeleton composition, and BunkFy pins.
2. Audit aggregate and persistence behavior for bounded session working sets, optimistic concurrency, indexes, provider parity, retention, and multi-replica operation.
3. Threat-model password, recovery, verification, refresh, step-up, external identity, OIDC, TOTP, and recovery-code flows, including enumeration, replay, downgrade, CSRF, token leakage, and rate-limit boundaries.
4. Verify contracts, API composition, error stability, cache policy, secret redaction, security-event data, and adapter extensibility without exposing implementation types.
5. Verify the holy-grail dependency graph mechanically: Auth depends only on Framework and its own projects; cross-module behavior stays in Extensions; Skeleton remains the canonical composition proof; BunkFy contains only product policy and adapters.
6. Add or tighten only the smallest tests, migrations, guards, documentation, or implementation required by proven findings.
7. Publish exact Framework/Auth revisions and verify standalone, Skeleton, and BunkFy validation lanes before closing the slice.

## Required Evidence

- zero-warning standalone build and focused tests;
- reusable-module boundary and dependency audit;
- PostgreSQL and SQL Server migration-drift checks and required relational coverage for provider-sensitive behavior;
- transitive vulnerability audit and explicit production configuration validation;
- current Auth, Framework, Skeleton, Extensions, and BunkFy tests mapped to their owning behavior with duplicate generic coverage removed;
- exact published heads with green required CI and clean consumer gitlinks.

## Initial Findings

1. The durable and process-local authentication-attempt limiters use separate allowance and failure-recording operations. Concurrent requests can all pass the allowance check before any failure is persisted, so the configured limit is not a strict multi-replica bound.
   - Replace the split protocol with one atomic acquisition operation that records an attempt before credential work.
   - Serialize only the normalized scope, purpose, and target key in relational persistence, using transaction-scoped PostgreSQL and SQL Server advisory locks.
   - Keep the process-local fallback atomic with compare-and-swap updates and keep successful authentication responsible for clearing prior attempts.
2. Username and external-identity uniqueness is correctly enforced by the database, but concurrent command losers can surface provider `DbUpdateException` details instead of a stable Auth result because Auth has no persistence retry behavior.
   - Add the dependency-neutral EF unique-constraint classifier to Framework, where equivalent provider inspection is already duplicated by reusable modules.
   - Add an Auth-owned one-retry command behavior so a collision is re-read and translated by existing domain/application checks.
3. Auth advertises PostgreSQL and SQL Server migrations, but its required Docker behavior lane currently exercises only PostgreSQL. Add matching provider-backed coverage for strict attempt acquisition and retain the broader PostgreSQL state/retention scenario.
4. Retention values are validated independently from application throttle windows. A deployment can therefore delete authentication or MFA-management failures while they are still part of an active limiting window. Reject such cross-option combinations during persistence composition.
5. External-identity linking checks `LoginDateTimeUtc` instead of the persisted authentication evidence timestamp. Align it with the shared fresh-session authorization helper so password step-up refreshes eligibility and a recently created session cannot substitute stale evidence.
6. JWT access-token lifetime validation rejects only non-positive values. Add a conservative upper bound so a configuration typo cannot create effectively non-revocable long-lived bearer credentials.
7. OpenID Connect return URLs are configured with callback paths but enforced as origin-only allowlists, and any rooted local path is accepted implicitly. Enforce explicit, exact callback scheme/authority/path entries while allowing only runtime query parameters on those paths.
8. Phone usernames accept exactly ten digits, which embeds a US-centric identity rule in a reusable module. Accept only canonical E.164-style identifiers so products can own locale-specific input parsing without weakening Auth lookup or uniqueness semantics.
9. Password-recovery cooldown and active-challenge replacement span separate challenge aggregates without serialization. Concurrent replicas can therefore issue multiple valid codes for one member. Serialize each member's recovery-request transaction through an Auth persistence adapter and re-read eligibility after acquiring the lock.
10. Session creation and rotation validate token hashes but do not reject a new refresh-token expiry that is already elapsed. Enforce the future-expiry invariant in the session entity even though application options normally produce a valid value.
11. The process-local attempt-limiter fallback has weaker input guards than persistent limiting and lets arbitrary targets grow its partition map without a bound. Share one Auth-owned normalized partition value across implementations and cap fallback partitions with expiry-aware cleanup and fail-closed saturation.
12. Multi-factor challenge creation revokes prior active challenges but does not serialize that replacement transaction. Concurrent primary authentications can therefore leave more than one active challenge despite the intended single-active-challenge behavior. Serialize replacement per scoped member through an Auth-owned port backed by the generic relational key lock.
13. Enabled OpenID Connect providers accept authority URLs with embedded credentials, query strings, or fragments, and silently discard malformed scope entries. Reject ambiguous authorities and invalid or unbounded OAuth scopes and credentials at startup.
14. The generic command unit-of-work behavior saves after a successful handler but does not open a transaction around the handler. Transaction-scoped coordination ports therefore fail under real dispatch even though direct integration tests can pass with manually opened transactions. Add an optional dependency-neutral transaction lifecycle to Framework and implement it in the EF unit of work.
15. Refresh-token reuse revokes active sessions inside the aggregate and then returns a failed result. The command unit-of-work intentionally skips failed results, so the security response is not durable. Represent this security-negative outcome as a successful internal completion, commit the revocation and security event, and map the completion back to a stable public failure at the API edge.
16. Several credential-proof validators check only for presence. Oversized usernames, passwords, access tokens, refresh tokens, MFA challenge tokens, and factor codes can therefore reach password hashing, JWT parsing, or keyed hashing and cause avoidable resource use or, for an oversized login username, an unhandled empty attempt partition. Publish Auth-owned input limits and reject oversized material consistently at the command boundary.
17. Refresh-token rotation extends `RefreshTokenExpiresAtUtc` from the current time without an absolute session bound. A continuously refreshed session can therefore remain valid indefinitely, including after its original authentication evidence becomes stale. Add an Auth-owned absolute session lifetime, enforce it in the domain for ordinary refreshes, and reset it only through explicit reauthentication.
18. Authenticated password changes, password removal, and external-identity unlinking mutate authenticators without rotating the current session and leave sibling sessions established through the changed or removed authenticator active. Require current refresh proof, rotate the authorized session, and revoke affected sibling sessions atomically. Keep refresh material in bearer contracts and dedicated HttpOnly-cookie browser routes rather than exposing it to browser application code.
19. Authentication evidence accepts timestamps later than the operation clock, and the fresh-session check treats those future values as fresh. Future evidence can therefore extend the absolute session deadline and bypass recency policy. Reject future session and challenge evidence, require second-factor evidence to be monotonic, and bound freshness on both sides of the current clock.
20. Password-recovery confirmation invokes the password blocklist before authenticating the one-time recovery challenge. A public caller can therefore amplify work against a remote breach-check adapter and receive password-policy responses without a valid challenge. Resolve and validate the challenge/member first, then invoke the blocklist before consuming or mutating recovery state.
21. Email-verification confirmation returns the stable public invalid-code error only when no token row is found; a stored expired token leaks a different domain error. Normalize all invalid, expired, inactive-email, and missing-token outcomes at the application boundary.
22. Several sensitive handlers authorize session or challenge freshness, await persistence or a pluggable password/factor adapter, and then mutate using the earlier timestamp. Re-read the clock and revalidate freshness immediately before security state changes so a slow dependency cannot extend an expired authorization window.
23. External-authentication handoff validation accepts undefined intent values and sign-in handoffs carrying link targets. Enforce the complete intent/target shape in both command validation and the service boundary so optional adapters cannot persist ambiguous exchanges.
24. Disabled members can reach MFA challenge creation after a valid primary credential and can update external-authentication or verification-request state before a later session mutation rejects them. Make disabled state fail before challenge creation and before authentication-adjacent domain mutations.
25. JWT session revocation is immediate for refresh and session-bound mutations but stateless bearer access remains valid until token expiry. Document that guarantee explicitly, retain a short default, and leave optional online introspection to hosts whose product risk justifies its per-request availability and latency cost.
26. Auth admin permissions are used globally by `AuthProfile.Global(...)` and in a concrete scope by `AuthProfile.ScopeAware()`, but their metadata can currently declare only one of those requirements and incorrectly advertises all operations as scoped. Add a dependency-neutral `GlobalOrScoped` Framework requirement for profile-dependent permissions and use it in Auth without changing exact-scope runtime authorization.
27. Public and browser registration plus administrative member creation bind username type through endpoint-local `JsonElement` request members. Generated OpenAPI therefore exposes `usernameType` as `unknown` even though Auth already owns a stable string enum contract. Bind the public contract and enum directly so generated clients receive `email | phone`; malformed enum JSON remains an HTTP payload error, while command validation continues to protect non-HTTP callers.
28. Several public, browser, OpenID Connect, and administrative endpoints return typed, accepted, no-content, or redirect success results through `IResult` helpers without explicit response metadata. Swagger consequently reports generic bodyless `200` responses. Declare each real success status and response type so generated clients match runtime behavior without changing endpoint execution.
29. Administrative create/reset-password endpoints can return one-time generated passwords when the host explicitly enables that capability, but those responses do not disable intermediary or browser caching. Apply `no-store` and `no-cache` headers at both secret-capable Admin API boundaries; keep CLI generation as an intentional one-time terminal response.
30. The `Member` aggregate has cohesive ownership and already delegates child state to username, session, and external-identity entities, but its implementation has grown to 971 lines and obscures invariant review. Preserve one aggregate and split its implementation into core/lifecycle, session, and authentication-method partials without moving behavior or weakening transaction boundaries.
31. Session creation sampled the system clock inside token material generation and again when constructing session authentication evidence. A real advancing clock could therefore place registration evidence after the session login timestamp and correctly fail the domain timeline invariant. Pass one explicit authentication timestamp through every session-creation path and cover registration with an advancing-clock regression.
32. The durable authentication-attempt limiter opens an independent service scope so an attempt is committed before slow credential verification, but a scope-aware Auth profile did not restore the caller's Auth partition in that child scope. Preserve the independent transaction while restoring the normalized Auth scope before resolving `AuthDbContext`; retain the write guard and cover both relational providers through a non-default scope.

These findings do not change ownership: attempt policy, recovery serialization keys, and retry semantics remain Auth-owned; Framework receives only generic EF provider error classification and transaction-scoped key locking.

## Non-Goals

- workspace roles, permissions, organization membership, staff records, invitations, or product onboarding;
- BunkFy-specific screens, protected-operation choices, or business identity verification;
- implementing passkeys, SMS/email OTP, trusted devices, or mandatory MFA unless the audit proves a missing reusable prerequisite that belongs in Auth;
- selecting concrete OIDC providers, email transports, secret stores, or retention periods for every product;
- changing Framework merely to relocate Auth-specific behavior.

## Intentionally Deferred Capabilities

- Passkeys, email/SMS one-time-password authenticators, trusted-device policy, and additional external identity protocols belong in optional Auth adapters when a product needs them.
- Mandatory email verification, mandatory MFA, high-risk-operation assurance mapping, and immediate online bearer-session introspection remain host or product policy.
- Authentication email delivery, security notifications, and organization-membership reactions remain explicit cross-module Extensions.
- Concrete provider selection, secrets, key custody, retention periods, and deployment topology remain product composition and operations responsibilities.

## Verification Evidence

- Framework restore and zero-warning build passed; all 991 Framework tests passed.
- Auth restore and zero-warning build passed; all 294 non-Docker Auth tests passed.
- Required PostgreSQL/SQL Server relational integration lane passed all 3 Docker tests, including scope-aware durable-attempt coverage on both providers.
- PostgreSQL and SQL Server migration-drift checks passed with the absolute-session-lifetime migrations applied to both provider models.
- Auth boundary checks and `git diff --check` passed; Framework and Auth transitive package audits reported no vulnerable packages.
- The canonical Skeleton public and Admin hosts generated typed `UsernameType` schemas and the intended Auth success status/response contracts.
- Exact-head BunkFy Docker verification reopened the slice by exposing findings 31 and 32 plus stale consumer assertions for malformed typed enum payloads. The Auth repairs pass standalone validation; exact published-head consumer verification remains pending before this record returns to complete.

## Completion Criteria

- all previous Auth completion records are either verified against current source or corrected with explicit follow-up work;
- credential, token, session, recovery, assurance, external identity, and MFA paths have stable security invariants and bounded multi-replica behavior;
- provider adapters remain optional and protocol-specific while Auth core stays provider-neutral;
- module data and migrations remain Auth-owned, with no direct reusable-module dependency or product-specific source;
- Extensions and products consume only published contracts and own their respective cross-module and policy behavior;
- standalone Auth, required relational lanes, Skeleton, and BunkFy pass against exact published revisions;
- the task record names any intentionally deferred capability and its owning layer.
