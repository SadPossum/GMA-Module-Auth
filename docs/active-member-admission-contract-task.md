# Active Member Admission Contract Task

Status: implementation verified
Date: 2026-08-10

## Goal

Give trusted in-process consumers one narrow, Auth-owned way to prove that a
member is currently active and, when available, obtain that active member's
preferred verified email. Organization and product admission must not infer
account activity from a verified username row, and consumers must not query
Auth persistence directly.

## Finding

`IAuthMemberContactReader` intentionally resolves verified contact data even
when a member is disabled. That is useful for Auth-owned security delivery,
but it is insufficient for admission decisions:

- the Auth/Organizations invitation bridge verifies only the persisted email;
- BunkFy workspace creation, onboarding, and join policies do the same; and
- non-Auth notification email delivery can resolve a disabled member's
  address while a durable notification is waiting to be delivered.

A short-lived access token can therefore reach an admission decision after
the Auth member has been disabled. Treating contact existence as activity also
makes the cross-module contract ambiguous.

## Boundary Decision

1. Auth Contracts owns an `IAuthMemberAdmissionReader` and a small
   `AuthMemberAdmission` snapshot.
2. A non-null snapshot means the exact member exists and is active in the
   explicit Auth scope. Its preferred verified email remains optional.
3. Auth Persistence resolves member activity and contact in one no-tracking,
   provider-translatable query. Missing, disabled, or unknown-status members
   return no snapshot.
4. `IAuthMemberContactReader` remains unchanged for Auth-owned security
   delivery that may intentionally outlive account disablement.
5. GMA Extensions uses the admission reader for organization creation, every
   organization join operation, recipient-bound invitation verification, and
   non-Auth email destinations. Exact-address recovery/verification delivery
   and Auth-owned security alerts keep their existing semantics. The
   Notifications bridge supports an optional fixed Auth lookup scope so global
   identities are not queried in a product tenant scope.
6. BunkFy owns every workspace rule. Its creation, onboarding, and join paths
   require the active-member snapshot and apply their existing verified-email
   policy on top.
7. Framework, Organizations, Notifications, and product persistence remain
   unchanged.

## Security And Efficiency

- The contract is in-process only and exposes no credential, session, role,
  provider, disablement reason, or raw authentication evidence.
- Scope and member identity are exact and normalized by Auth.
- Activity and verified contact come from one database snapshot, avoiding a
  check-then-read race and a second query.
- Disabled and missing members are indistinguishable to admission consumers.
- Failures propagate so callers can preserve their existing unavailable or
  retry behavior rather than allowing admission on an uncertain read.

## Delivery

- [x] Add the Contracts snapshot/reader and Auth Persistence implementation.
- [x] Add focused active, disabled, unverified, missing, and cross-scope tests.
- [x] Move Auth/Organizations admission and non-Auth email resolution to the
  new contract while preserving Auth security-delivery behavior.
- [x] Move BunkFy workspace creation, onboarding, and join admission to the
  new contract and add regression coverage.
- [x] Keep source boundaries contract-only and synchronize solution/docs
  manifests.
- [x] Run one consolidated non-Docker gate per changed repository.
- [x] Prepare dependency-order publication; exact commit CI supplies the
  remaining relational and cross-repository evidence.

## Local Verification

- Auth: synchronized solution, zero-warning build, both-provider migration
  drift, 304 non-Docker tests, boundary, package, security, and release checks.
- GMA Extensions: zero-warning build, 44 tests, boundary, package, security,
  release, and solution checks.
- BunkFy Backend: complete `eng/verify.ps1` pass with a zero-warning build,
  all migration-drift checks, and the full fast suite including 59 integration
  tests; repository security and release checks also passed.
- The existing Auth relational CI lane covers the new admission query against
  PostgreSQL and SQL Server after publication; local Docker was intentionally
  not repeated during the slice.

## Done When

- a disabled or missing Auth member cannot pass reusable organization or
  BunkFy workspace admission through a retained verified username;
- non-Auth notification email no longer resolves a disabled account;
- Auth-owned security and exact-address recovery/verification delivery retain
  their intentional behavior;
- no consumer references Auth Application, Domain, Persistence, or database
  entities; and
- exact Auth, Extensions, Skeleton, BunkFy backend, and product-root revisions
  pass their required verification lanes.

## Not In This Slice

- online introspection of every bearer request;
- product roles, membership, employment, or workspace policy in Auth;
- changing access-token lifetime or session-revocation semantics;
- suppressing Auth-owned security alerts after disablement; or
- a remote identity/profile lookup API.
