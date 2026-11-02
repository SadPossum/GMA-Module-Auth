namespace Gma.Modules.Auth.Persistence.Admission;

using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence.Remembered;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;

/// <summary>Auth tracked invalidations cooperate at persistence, covering security methods and
/// remembered-device/proof changes without requiring private callers to touch Auth tables.</summary>
internal static class AuthAdmissionWriteGuard
{
    internal static AuthAdmissionLockKey[] ChangedKeys(AuthDbContext db)
    {
        db.ChangeTracker.DetectChanges();
        HashSet<AuthAdmissionLockKey> keys = [];
        foreach (EntityEntry entry in db.ChangeTracker.Entries().Where(entry =>
            entry.State is EntityState.Modified or EntityState.Deleted))
        {
            switch (entry.Entity)
            {
                case Member member:
                    Stable(entry, nameof(member.Id), nameof(member.ScopeId));
                    Add(member.ScopeId, member.Id.Value);
                    Add(Scope(entry), ((MemberId)entry.OriginalValues[nameof(Member.Id)]!).Value);
                    break;
                case MemberSession session:
                    Stable(entry, nameof(session.Id), nameof(session.ScopeId), nameof(session.MemberId));
                    Add(session.ScopeId, session.MemberId.Value, session.Id.Value);
                    Add(Scope(entry), ((MemberId)entry.OriginalValues[nameof(MemberSession.MemberId)]!).Value,
                        ((MemberSessionId)entry.OriginalValues[nameof(MemberSession.Id)]!).Value);
                    break;
                case RememberedBrowserDevice device:
                    Stable(entry, nameof(device.Id), nameof(device.ScopeId));
                    AddOptional(device.ScopeId, device.ActiveMemberId, device.ActiveSessionId);
                    AddOptional(Scope(entry), (Guid?)entry.OriginalValues[nameof(device.ActiveMemberId)],
                        (Guid?)entry.OriginalValues[nameof(device.ActiveSessionId)]);
                    break;
                case RememberedAccountProof proof:
                    Stable(entry, nameof(proof.Id), nameof(proof.ScopeId), nameof(proof.MemberId),
                        nameof(proof.DeviceId), nameof(proof.OriginalSessionId));
                    Add(proof.ScopeId, proof.MemberId, proof.OriginalSessionId);
                    Add(Scope(entry), (Guid)entry.OriginalValues[nameof(proof.MemberId)]!,
                        (Guid)entry.OriginalValues[nameof(proof.OriginalSessionId)]!);
                    break;
                default:
                    break;
            }
        }

        return AuthAdmissionLockKey.Ordered(keys);

        static string Scope(EntityEntry entry) => (string)entry.OriginalValues["ScopeId"]!;
        static void Stable(EntityEntry entry, params string[] properties)
        {
            if (properties.Any(property =>
                !Equals(entry.OriginalValues[property], entry.CurrentValues[property])))
            {
                throw new InvalidOperationException("Auth admission ownership identities cannot be rebound by an invalidation.");
            }
        }
        void Add(string scope, Guid member, Guid? session = null)
        {
            keys.Add(AuthAdmissionLockKey.Subject(scope, member));
            if (session is not null)
            {
                keys.Add(AuthAdmissionLockKey.Session(scope, member, session.Value));
            }
        }
        void AddOptional(string scope, Guid? member, Guid? session)
        {
            if (member is not null)
            {
                Add(scope, member.Value, session);
            }
            else if (session is not null)
            {
                throw new InvalidOperationException("Auth device admission identity is incomplete.");
            }
        }
    }

    internal static Guid[] ChangedDeviceIds(AuthDbContext db)
    {
        return db.ChangeTracker.Entries().Where(entry => entry.State is EntityState.Modified or EntityState.Deleted)
            .SelectMany<EntityEntry, Guid>(entry => entry.Entity switch
            {
                RememberedBrowserDevice device => [device.Id],
                RememberedAccountProof proof => [proof.DeviceId],
                _ => [],
            }).Distinct().Order().ToArray();
    }

    internal static async Task<AuthAdmissionLockKey[]> ReadPersistedDeviceKeysAsync(AuthDbContext db,
        Guid[] deviceIds, CancellationToken cancellationToken)
    {
        if (deviceIds.Length == 0)
        {
            return [];
        }
        var rows = await db.RememberedBrowserDevices.IgnoreQueryFilters().AsNoTracking()
            .Where(device => deviceIds.Contains(device.Id))
            .Select(device => new { device.Id, device.ScopeId, device.ActiveMemberId, device.ActiveSessionId })
            .ToArrayAsync(cancellationToken).ConfigureAwait(false);
        if (rows.Length != deviceIds.Distinct().Count())
        {
            throw new InvalidOperationException("Auth invalidation device history is unavailable.");
        }
        List<AuthAdmissionLockKey> keys = [];
        foreach (var row in rows)
        {
            var expectedScopes = db.ChangeTracker.Entries().Where(entry => entry.State is EntityState.Modified or EntityState.Deleted)
                .Select(entry => entry.Entity switch
                {
                    RememberedBrowserDevice device when device.Id == row.Id => device.ScopeId,
                    RememberedAccountProof proof when proof.DeviceId == row.Id => proof.ScopeId,
                    _ => null,
                }).Where(scope => scope is not null).Distinct().ToArray();
            if (expectedScopes.Length != 1 || expectedScopes[0] != row.ScopeId)
            {
                throw new InvalidOperationException("Auth invalidation device scope changed.");
            }
            if (row.ActiveMemberId is Guid member)
            {
                keys.Add(AuthAdmissionLockKey.Subject(row.ScopeId, member));
                if (row.ActiveSessionId is Guid session)
                {
                    keys.Add(AuthAdmissionLockKey.Session(row.ScopeId, member, session));
                }
            }
            else if (row.ActiveSessionId is not null)
            {
                throw new InvalidOperationException("Auth device admission identity is incomplete.");
            }
        }
        return AuthAdmissionLockKey.Ordered(keys);
    }

    internal static Task AcquireAsync(AuthDbContext db, IEnumerable<AuthAdmissionLockKey> keys,
        CancellationToken cancellationToken, string? expectedOwnerIdentity = null) =>
        AuthAdmissionLockKey.AcquireAsync(db, keys, EfTransactionKeyLockMode.Exclusive, cancellationToken, expectedOwnerIdentity);
}
