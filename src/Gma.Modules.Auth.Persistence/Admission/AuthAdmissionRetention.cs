namespace Gma.Modules.Auth.Persistence.Admission;

using System.Data;
using Microsoft.EntityFrameworkCore;

/// <summary>The three raw retention deletes which can remove session-admission inputs must
/// cooperate too. Candidate selection is bounded by the existing retention policy. Re-read exact
/// identities under guards, and recheck the original expiry/revocation predicates in the delete.</summary>
internal static class AuthAdmissionRetention
{
    internal static async Task<int> DeleteAsync(AuthDbContext db,
        Func<CancellationToken, Task<Guid[]>> readDeviceIds,
        Func<CancellationToken, Task<AuthAdmissionLockKey[]>> readKeys,
        Func<CancellationToken, Task<int>> delete, CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql())
        {
            return await delete(cancellationToken).ConfigureAwait(false);
        }
        if (db.Database.CurrentTransaction is not null || System.Transactions.Transaction.Current is not null ||
            db.ChangeTracker.HasChanges())
        {
            throw new InvalidOperationException("Auth retention admission fencing requires its own clean transaction.");
        }

        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            .ConfigureAwait(false);
        Guid[] devices = await readDeviceIds(cancellationToken).ConfigureAwait(false);
        string ownerIdentity = await AuthAdmissionLockKey.AcquireDeviceRowsAsync(db, devices, cancellationToken).ConfigureAwait(false);
        Guid[] currentDevices = await readDeviceIds(cancellationToken).ConfigureAwait(false);
        if (!devices.Distinct().Order().SequenceEqual(currentDevices.Distinct().Order()))
        {
            throw new InvalidOperationException("Auth retention device identities changed; retry the bounded batch.");
        }
        AuthAdmissionLockKey[] before = AuthAdmissionLockKey.Ordered(await readKeys(cancellationToken).ConfigureAwait(false));
        await AuthAdmissionWriteGuard.AcquireAsync(db, before, cancellationToken, ownerIdentity).ConfigureAwait(false);
        AuthAdmissionLockKey[] after = AuthAdmissionLockKey.Ordered(await readKeys(cancellationToken).ConfigureAwait(false));
        if (!before.SequenceEqual(after))
        {
            throw new InvalidOperationException("Auth retention admission identities changed; retry the bounded batch.");
        }
        int count = await delete(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return count;
    }
}
