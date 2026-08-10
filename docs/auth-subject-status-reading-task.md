# Auth Subject Status Reading Task

Status: complete
Date: 2026-08-10

## Goal

Expose one narrow Auth Contracts capability through which a trusted in-process
orchestrator can resolve an opaque account subject to its canonical identity and
current Auth status. Keep product authorization, ownership eligibility, profile
data, and cross-module workflow state outside Auth.

## Problem

An orchestrator that assigns a durable relationship such as an initial tenant
owner must not accept an arbitrary subject string without proving that Auth owns
the account. Direct Auth-table queries break module ownership, caller-selected
scope bypasses undermine Auth's composition boundary, and an administration or
HTTP endpoint would expose an account-enumeration surface wider than the
in-process workflow needs.

Subject spelling is also part of authorization identity. Auth access tokens use
the member id as a canonical lower-case `D` GUID while downstream modules may
compare opaque subjects ordinally. Merely accepting another parseable GUID form
would let a caller verify one account but persist a subject that never matches
that account's token.

## Contract Decision

1. Auth Contracts exposes `IAuthSubjectStatusReader` and
   `AuthSubjectStatusSnapshot` only. The snapshot contains the persisted Auth
   scope, canonical subject id, and existing stable `MemberStatus` value.
2. `FindAsync(subjectId)` treats the subject as opaque to the caller. Scope is
   never caller input: the reader uses the current fixed or ambient
   `IAuthScopeContext`. Auth accepts a non-empty parseable member GUID and
   returns the subject in lower-case `D` form.
3. Invalid, empty, zero, and missing subjects return `null`. A disabled member
   remains discoverable as `MemberStatus.Disabled`; an unrecognized persisted
   status maps to `MemberStatus.Unknown` and consumers must fail closed.
4. The persistence reader requires an enabled, valid Auth scope, captures it,
   keeps the normal `AuthDbContext` query filter, and adds an explicit ordinal
   row-scope predicate. A disabled filter or a disagreement between the reader
   scope and DbContext fails closed. The reader returns the actual persisted
   scope, reads no navigation or contact data, and uses no tracking. Exact scope
   identity continues to be enforced by the existing provider models and SQL
   Server scope-identity migration.
5. The capability is absent from ordinary Auth composition. A trusted
   composition root must call `AddAuthSubjectStatusReader()`. Registration is
   idempotent and replacement-friendly.
6. No HTTP, administration API, CLI, integration event, database field,
   migration, cache, or generic Framework abstraction is added.

## Trust, Privacy, And Authorization

The reader is account-enumeration capability even though it returns no username,
email, credential, provider, session, MFA, recovery, or disable-reason data. It
must be composed only into a trusted orchestration host and must not be forwarded
as a public lookup endpoint.

Auth attests only that a subject exists in one Auth scope and reports its account
status. Auth does not decide whether that account may own a hostel, workspace,
organization, subscription, or any other product resource. The product performs
and audits that authorization. For the common initial-owner rule, the product may
treat only `MemberStatus.Active` as eligible and must treat `Disabled`, `Unknown`,
and `null` as fail-closed outcomes.

Email verification, MFA enrollment, authentication freshness, identity proof,
commercial state, sanctions policy, and staff approval are independent product
policies. They are intentionally not implied by `Active` and can be added by the
product without widening this Auth seam.

## Consumer Obligations

- Compose the intended Auth profile. `AuthProfile.Global("identity")` always
  reads its fixed Auth-owned scope; `AuthProfile.ScopeAware()` reads only the
  ambient scope restored before the scoped reader and DbContext are resolved.
- Persist and use the returned canonical `SubjectId`; never persist the original
  candidate after a successful lookup.
- Treat the snapshot as point-in-time evidence, not a lease or permanent grant.
  Account disablement and re-enablement continue independently through Auth.
- Check status immediately before the first external provisioning attempt and
  durably retain the canonical subject with that workflow attempt. If the remote
  provisioning call may already have committed, recover with the same idempotent
  request rather than selecting a different owner. Re-evaluate current status
  before declaring the product resource operational.
- Never silently replace a now-disabled owner inside the same idempotent attempt.
  Owner replacement is a separately authorized and auditable product workflow.
- Apply endpoint authorization, throttling, audit, and non-cacheable response
  policy at the product surface. This contract is not such a surface.

## Composition

```csharp
builder.AddAuthModule(AuthProfile.Global("identity"));
builder.AddAuthSubjectStatusReader();
```

Product application code depends only on `Gma.Modules.Auth.Contracts`. The host
composition root owns the Persistence registration call.

## Verification

- `dotnet build Gma.Modules.Auth.slnx --no-restore -m:1` succeeds with zero
  warnings and zero errors.
- `dotnet test Gma.Modules.Auth.slnx --no-build --filter "Category!=Docker"`
  passes all 320 unit and contract tests.
- `GMA_REQUIRE_DOCKER_TESTS=true dotnet test
  tests/Gma.Modules.Auth.IntegrationTests/Gma.Modules.Auth.IntegrationTests.csproj`
  passes all three relational integration tests. The PostgreSQL and SQL Server
  lanes both exercise the reader against case-distinct scopes, active and
  disabled members, and canonical subject output.
- All 17 focused status-reader and contract tests prove invalid, zero, and
  missing subjects return `null`, malformed input does not touch persistence,
  unknown stored status fails closed, reads are
  no-tracking, cancellation reaches the query, a fixed global profile cannot see
  another scope, scope-aware reads follow only the restored ambient scope in a
  fresh scoped lifetime, and missing, disabled, invalid, or mismatched scope
  state fails closed.
- Complete Auth composition leaves the capability absent. Explicit registration
  is idempotent, scoped, and preserves a caller replacement.
- Framework solution synchronization, Auth boundaries, SQL Server and PostgreSQL
  migration drift, repository security policy, and repository release policy
  all pass.
- `dotnet list Gma.Modules.Auth.slnx package --vulnerable
  --include-transitive` reports no vulnerable direct or transitive packages.

## Not In This Slice

- organization or product ownership policy;
- public subject discovery or bulk account lookup;
- verified-email, MFA, assurance, KYC/KYB, profile, or permission projections;
- account creation, activation, disablement, or repair;
- caching status beyond the caller's durable workflow evidence; or
- Framework, schema, or migration changes.
