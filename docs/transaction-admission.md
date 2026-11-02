# Transaction admission for an authenticated subject and session

`IAuthTransactionAdmission` supplies Auth identity/session facts held against cooperating
persisted invalidations. It supplies no financial permission, account/history certification,
staff entitlement or authority to act for another subject. The consumer must
derive its actor from trusted authentication and enforce actor = financial subject.

The first implementation supports the exact borrowed PostgreSQL `ReadCommitted` transaction
on the configured Auth database. It rejects ambient, lost, mismatched and unsupported
transactions, noncanonical scopes, different configured database targets, multi-host and
socket endpoints. A borrowed read context never owns, commits or rolls back the connection
or transaction. Disposing the fence does not release its owner's transaction locks.

Admission reuses the current member/session predicates, including remembered-device,
generation, security epoch, proof, restore epoch and pepper-version checks. Shared subject
and session guards last until owner commit/rollback. Revalidation checks current predicates,
expiry, configuration snapshot and the server transaction/backend/lifetime identity; a
recycled provider transaction object cannot retain old lock ownership. Unsupported or
uncertain coordination denies, and uncertain partial lock acquisition requires rollback.

## Cooperating writers and ordering

The existing `EfTransactionKeyLock` Shared/Exclusive primitive supplies the new Auth advisory
keys. Consumers retain their own distinct lock identities and accounting order.

Auth device rows retain their existing `FOR UPDATE` lock first, in sorted device order.
Subject advisory keys follow, then session keys in one canonical order. Coordination spans
all Auth contexts sharing the logical owner transaction. New earlier keys and Shared to
Exclusive upgrades are rejected before an advisory wait. A writer cannot acquire a new
device row after acquiring advisory keys. Auth writers must not call back into consumers while
holding these guards. Consumers retain their own lock order before requesting
Auth admission; an admission reader uses MVCC reads and does not acquire device row locks.

Tracked member, session, device and proof modifications/deletions cooperate through
`AuthDbContext.SaveChangesAsync`. Original/current identities are included; immutable
ownership coordinates cannot be rebound by invalidation. Device/proof parent rows are
locked and their persisted active owner/session is reread before advisory admission keys,
covering stale or previously unbound tracked devices. The existing remembered-browser
begin path participates before its row reload. Raw session/proof/device retention deletes
use owned bounded transactions, preserve device-parent row order, reread identities and
recheck existing retention eligibility before deleting. Other raw retention categories do
not supply admission inputs.

An already explicit Auth transaction remains owned by its caller. A direct asynchronous
Auth save creates an owned transaction when fencing is required and none exists; it accepts
tracked changes only after successful commit. PostgreSQL synchronous invalidations are
unsupported. Existing SQL Server behavior is retained, but the new admission capability
does not claim a SQL Server guarantee.

## Guarantee and limits

A cooperating revocation cannot commit first and then permit a stale admitted operation
to commit. A valid operation may commit before a waiting revocation. This does not undo
already committed valid operations, erase financial history on logout, freeze time, or coordinate
out-of-band SQL/configuration changes. Check expiry immediately before owner completion.
Financial grants, restrictions, policy epochs, binding/history evidence and immutable
accounting receipts remain in their existing private owners outside Auth.

Consumer-side establishment and economic effects remain outside this module. This change does
not implement a history certificate producer, initial account establishment composition,
guest/staff financial grants, production wiring, activation, deployment or migration.

## Qualification separation

Provider-free tests check contracts, scoped keys, tracked invalidation coverage and default
denial; they cannot prove PostgreSQL locking. The separately gated PostgreSQL tests require
an externally owned loopback database named `gma_auth_admission_<32 lowercase hex>` and an
exact owner comment. They start no Docker/services, use synthetic records, and inspect only
known owned backend PIDs when proving lock waits. They cover commit/revocation ordering,
retention/device order, stale device ownership, unsupported transactions, lost/expired
fences and commit failure. They are not assembled-host, login, proxy or browser acceptance.

Validation on 2026-11-02: the module solution builds; 374 provider-free tests pass
(14 database-gated declarations skip without the owned fixture); all 27 expanded owned
PostgreSQL transaction-admission cases pass. These results do not establish consumer-host
or deployment acceptance.
