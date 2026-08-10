# Active Bearer Session Admission Task

Status: implementation in progress
Date: 2026-08-10

## Goal

Let applications that compose GMA Auth choose whether a validly signed access
token is sufficient for a request or whether the exact Auth member and session
must still be active. Session revocation and account disablement must be able to
deny a retained bearer immediately without moving product authorization into
Auth or requiring every product module to query Auth.

## Finding

Auth access tokens are self-contained and currently remain valid until their
configured expiry. Disabling a member, signing out, password recovery, MFA
reset, and administrative session revocation all deactivate Auth sessions, but
an already issued bearer can still authenticate for up to the remaining access
token lifetime. BunkFy uses a 15-minute lifetime, so organization offboarding is
immediate while global account or session revocation is not.

## Boundary Decision

1. Auth Contracts owns one narrow `IAuthSessionAdmissionReader`. It answers
   whether the exact scope, member, and session are currently active.
2. Auth Persistence implements the reader with one no-tracking, provider-
   translatable query over Auth-owned member and session state. Admission
   requires an active member, an active session, an exact identity match, and
   an unexpired absolute session lifetime.
3. Auth's JWT bearer adapter owns optional online admission after signature,
   issuer, audience, and access-token lifetime validation. It preserves any
   existing `OnTokenValidated` handler and rejects malformed or inactive Auth
   principals without distinguishing the cause.
4. `Auth:BearerAdmission:Mode` supports `TokenLifetime` for the existing
   stateless behavior and `ActiveSession` for immediate revocation. The default
   remains `TokenLifetime` for compatibility; production products must select
   and guard their intended mode explicitly.
5. Skeleton demonstrates `ActiveSession`, and BunkFy selects it for its Public
   and Admin APIs. Worker and CLI hosts do not perform bearer admission.
6. Framework, Organizations, AccessControl, product modules, and GMA Extensions
   remain unchanged.

## Security And Efficiency

- Active-session mode performs one indexed Auth read per authenticated request;
  anonymous requests and token-lifetime mode perform none.
- The lookup uses the session primary key plus exact member/scope predicates and
  does not hydrate aggregates, usernames, refresh-token hashes, or history.
- No positive cache is introduced because it would recreate a revocation-delay
  window or require a new distributed invalidation protocol. A bounded cache can
  be added later as a separate, explicit consistency tradeoff.
- Persistence failures propagate and therefore fail closed; they are not
  converted into an allow decision or a misleading inactive-account result.
- The adapter exposes no member status, session state, disablement reason, or
  credential data to callers.

## Delivery

- [x] Add the Contracts reader and Auth Persistence implementation.
- [x] Add bearer admission options, validation, composable event wiring, and
  focused contract/persistence/adapter tests.
- [x] Prove active, signed-out, disabled, expired, malformed, and cross-scope
  behavior without adding a migration.
- [x] Configure Skeleton and BunkFy Public/Admin APIs for `ActiveSession` and
  guard the composition from accidental downgrade.
- [x] Extend the existing real-provider Auth lifecycle proof so the same access
  token is denied immediately after sign-out.
- [ ] Run one consolidated non-Docker gate per changed repository, then publish
  and use exact CI for the final relational and composition evidence.

## Done When

- strict mode rejects the same otherwise-unexpired token after any Auth session
  revocation path or member disablement;
- active tokens continue through existing bearer and SignalR handlers;
- token-lifetime mode preserves the previous stateless behavior;
- the hot admission query is bounded, no-tracking, and proven on both supported
  providers by the existing Auth relational lane;
- BunkFy cannot silently ship its Public or Admin API in token-lifetime mode;
  and
- exact Auth, Skeleton, BunkFy backend, and product-root revisions pass their
  required validation lanes.

## Not In This Slice

- product roles, workspace membership, staff employment, or permission policy;
- remote OAuth/OIDC token introspection or reference tokens;
- Redis, NATS, or process-local admission caching;
- per-token revocation within one Auth session; or
- changing access-token, refresh-token, or absolute-session lifetimes.

## Local Evidence

- Auth build, boundary, migration-drift, repository security/release, solution
  synchronization, package-vulnerability, and all 310 non-Docker tests pass.
- Focused adapter and persistence coverage passes for strict and compatibility
  modes, malformed claims, inactive sessions, disabled members, expiry, and
  exact scope/member/session matching.
- BunkFy's existing Auth lifecycle passes through its real API host against SQL
  Server and PostgreSQL and rejects the same unexpired bearer after sign-out.
- Skeleton's matching cross-replica lifecycle proof compiles; its Docker run is
  intentionally deferred because the product lifecycle already exercises the
  same relational implementation on both supported providers in this slice.
