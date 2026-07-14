# Global Identity With Ambient Tenancy Task

Status: completed
Date: 2026-07-14

## Goal

Make `AuthProfile.Global()` safely composable in an application that also enables ambient Tenancy for other modules. Auth identity remains stored and queried in one fixed global Auth scope while tenant-aware product modules continue to use the request/background tenant scope.

Preserve `AuthProfile.ScopeAware()` behavior and every existing Auth security invariant. This task does not add organizations, memberships, invitations, product roles, or workspace policy to Auth.

## Current Limitation

Auth handlers, persistence, API checks, and OpenID Connect handoffs currently resolve the shared ambient `IScopeContext`. The global profile works by changing `Scoping:LocalDefaultScopeId` and is documented for hosts that omit Tenancy. When Tenancy is enabled, its scope bridge replaces the shared context, so Auth persistence follows the selected tenant instead of the configured global Auth scope.

## Design

Add one Auth-owned scope abstraction used by every Auth layer:

- global profile: fixed normalized global scope, filtering/writes always enforced, and restored state must match the fixed value;
- scope-aware profile: adapter over the existing ambient `IScopeContextAccessor`, preserving header/callback restoration and token-scope matching;
- conflicting Auth profile registrations in one service collection fail during composition;
- existing no-profile application/persistence registration overloads keep the scope-aware compatibility default.

The shared ambient scope remains untouched. Auth does not mutate a tenant request to `global`, and global Auth endpoints do not require a tenant header.

## Required Changes

- introduce `IAuthScopeContext` in the Auth application public seam;
- register fixed or ambient implementations from `AuthProfile`;
- use the Auth context in commands, queries, external handoff behavior, `AuthDbContext`, API token checks, and OIDC contributor/callback restoration;
- pass the selected profile through Auth API/Admin API/Admin CLI composition and persistence registration;
- remove the legacy global-profile mutation of the host's local default scope;
- update design-time/test contexts and documentation;
- add no migrations because the schema and scope column do not change.

## Security Invariants

- a tenant header cannot select another Auth member partition under the global profile;
- the global query filter reads only the configured global scope even if legacy rows exist;
- writes with a non-global scope fail under the global profile;
- scope-aware token scope matching remains exact;
- global tokens remain global identity/session tokens and are not tenant grants;
- OIDC handoff scope is protected state, normalized, and accepted only by the selected Auth profile;
- global OIDC callbacks never overwrite ambient Tenancy;
- profile conflicts fail closed at startup.

## Verification

- profile/DI tests prove fixed and ambient context selection plus conflict rejection;
- a host test composes an enabled tenant-like ambient context with global Auth and resolves `tenant-a` ambient plus `global` Auth scopes simultaneously;
- persistence tests prove global filtering and write rejection against rows from another scope;
- application tests cover register/login/refresh/external exchange through the Auth context;
- OIDC tests cover global fixed restoration, scope-aware restoration, missing/mismatched protected scope, and disabled baseline context compatibility;
- existing Auth focused tests, provider migration drift, package build, vulnerability audit, and `git diff --check` pass;
- GMA Skeleton later composes the published Auth change with Tenancy as the cross-repository acceptance proof.

## Completion Criterion

The slice is complete when global Auth and ambient tenant resource scope coexist in one process without scope mutation or data leakage, all Auth paths consistently use the selected profile context, scope-aware compatibility remains green, and focused repository proof passes.

## Completion Evidence

- the full Auth suite passes: 160 tests;
- mixed-scope composition resolves `tenant-a` for the host and `identity` for Auth in the same service scope;
- persistence proof filters legacy tenant rows and rejects a tenant write under fixed global Auth;
- fixed and ambient OIDC handoff tests pass, including mismatch and missing-state rejection;
- SQL Server and PostgreSQL report no pending model changes;
- the transitive vulnerability audit reports no vulnerable packages;
- solution build, `git diff --check`, and profile-conflict tests pass.
