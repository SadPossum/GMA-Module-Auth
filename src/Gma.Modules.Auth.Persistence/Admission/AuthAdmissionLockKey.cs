namespace Gma.Modules.Auth.Persistence.Admission;

using System.Data;
using System.Data.Common;
using System.Text.Json;
using System.Runtime.CompilerServices;
using System.Globalization;
using Gma.Framework.Naming;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

/// <summary>New Auth-owned lock identities. Do not substitute these for existing Points or
/// remembered-device row locks. Every cooperating reader/writer uses this exact key derivation.</summary>
internal readonly record struct AuthAdmissionLockKey(int Kind, string ScopeId, Guid MemberId, Guid SessionId)
{
    private static readonly ConditionalWeakTable<DbTransaction, TransactionState> States = [];
    internal static AuthAdmissionLockKey Subject(string scope, Guid member) =>
        new(0, ScopeIds.Normalize(scope, nameof(scope)), RequireId(member), Guid.Empty);

    internal static AuthAdmissionLockKey Session(string scope, Guid member, Guid session) =>
        new(1, ScopeIds.Normalize(scope, nameof(scope)), RequireId(member), RequireId(session));

    internal string Resource => "gma/auth/transaction-admission/v1/" + (this.Kind == 0 ? "subject/" : "session/") +
        JsonSerializer.Serialize(new[] { this.ScopeId, this.MemberId.ToString("D"), this.SessionId.ToString("D") });

    internal static AuthAdmissionLockKey[] Ordered(IEnumerable<AuthAdmissionLockKey> keys) => keys.Distinct()
        .OrderBy(key => key.Kind).ThenBy(key => key.ScopeId, StringComparer.Ordinal)
        .ThenBy(key => key.MemberId).ThenBy(key => key.SessionId).ToArray();

    internal static void RequireTransaction(AuthDbContext db, DbTransaction transaction)
    {
        if (!db.Database.IsNpgsql() || System.Transactions.Transaction.Current is not null ||
            db.Database.CurrentTransaction is null ||
            !ReferenceEquals(db.Database.CurrentTransaction.GetDbTransaction(), transaction) ||
            !ReferenceEquals(db.Database.GetDbConnection(), transaction.Connection) ||
            transaction.Connection is not { State: ConnectionState.Open } ||
            transaction.IsolationLevel != IsolationLevel.ReadCommitted)
        {
            throw new InvalidOperationException("Auth admission requires the exact active PostgreSQL ReadCommitted transaction.");
        }
    }

    internal static async Task<string> AcquireAsync(AuthDbContext db, IEnumerable<AuthAdmissionLockKey> keys,
        EfTransactionKeyLockMode mode, CancellationToken cancellationToken, string? expectedOwnerIdentity = null)
    {
        DbTransaction transaction = db.Database.CurrentTransaction?.GetDbTransaction() ??
            throw new InvalidOperationException("Auth admission requires an active transaction.");
        RequireTransaction(db, transaction);
        TransactionState state = States.GetValue(transaction, static _ => new());
        await state.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string identity = await BindLiveTransactionAsync(db, transaction, state, cancellationToken).ConfigureAwait(false);
            if (expectedOwnerIdentity is not null && identity != expectedOwnerIdentity)
            {
                throw new InvalidOperationException("Auth admission owner transaction changed.");
            }
            AuthAdmissionLockKey[] requested = Ordered(keys);
            ValidateNextAccess(state.Held, requested, mode);
            foreach (AuthAdmissionLockKey key in requested)
            {
                if (state.Held.ContainsKey(key))
                {
                    continue;
                }
                try
                {
                    await EfTransactionKeyLock.AcquireAsync(db, key.Resource, mode, cancellationToken).ConfigureAwait(false);
                    state.Held.Add(key, mode); // Record each acquisition before any further await/check.
                    RequireTransaction(db, transaction);
                }
                catch
                {
                    // A canceled provider command can have acquired its lock before reporting
                    // failure. No later Auth operation may guess the transaction's lock state.
                    state.Poisoned = true;
                    throw;
                }
            }
            return identity;
        }
        finally
        {
            state.Gate.Release();
        }
    }

    internal static void ValidateNextAccess(IReadOnlyDictionary<AuthAdmissionLockKey, EfTransactionKeyLockMode> held,
        IEnumerable<AuthAdmissionLockKey> keys, EfTransactionKeyLockMode mode)
    {
        if (mode is not (EfTransactionKeyLockMode.Shared or EfTransactionKeyLockMode.Exclusive))
        {
            throw new InvalidOperationException("Auth admission lock mode is unsupported.");
        }
        AuthAdmissionLockKey[] requested = Ordered(keys);
        if (mode == EfTransactionKeyLockMode.Exclusive && requested.Any(key =>
            held.TryGetValue(key, out var existing) && existing == EfTransactionKeyLockMode.Shared))
        {
            throw new InvalidOperationException("Auth admission lock upgrades are unsupported; use a separate owner transaction.");
        }
        AuthAdmissionLockKey[] all = Ordered(held.Keys.Concat(requested));
        int highestHeld = Array.FindLastIndex(all, held.ContainsKey);
        if (all.Take(highestHeld + 1).Any(key => !held.ContainsKey(key)))
        {
            throw new InvalidOperationException("Auth transaction admission keys must retain one canonical order across contexts.");
        }
    }

    internal static async Task<string> AcquireDeviceRowsAsync(AuthDbContext db, IEnumerable<Guid> deviceIds,
        CancellationToken cancellationToken)
    {
        DbTransaction transaction = db.Database.CurrentTransaction?.GetDbTransaction() ??
            throw new InvalidOperationException("Auth device invalidation requires an active transaction.");
        RequireTransaction(db, transaction);
        TransactionState state = States.GetValue(transaction, static _ => new());
        await state.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string identity = await BindLiveTransactionAsync(db, transaction, state, cancellationToken).ConfigureAwait(false);
            Guid[] requested = deviceIds.Distinct().Order().ToArray();
            if (requested.Contains(Guid.Empty))
            {
                throw new InvalidOperationException("Auth device identity is required.");
            }
            Guid[] missing = requested.Where(id => !state.DeviceRows.Contains(id)).ToArray();
            if (missing.Length != 0 && (state.Held.Count != 0 || (state.DeviceRows.Count != 0 &&
                missing.Any(id => id.CompareTo(state.DeviceRows.Max()) < 0))))
            {
                throw new InvalidOperationException("Auth device rows must precede admission keys in canonical order.");
            }
            foreach (Guid id in missing)
            {
                try
                {
                    // Same existing Auth row lock, not a new advisory substitute.
                    await db.Database.ExecuteSqlInterpolatedAsync(
                        $"SELECT 1 FROM auth.remembered_browser_devices WHERE \"Id\" = {id} FOR UPDATE",
                        cancellationToken).ConfigureAwait(false);
                    state.DeviceRows.Add(id);
                    RequireTransaction(db, transaction);
                }
                catch
                {
                    state.Poisoned = true;
                    throw;
                }
            }
            return identity;
        }
        finally
        {
            state.Gate.Release();
        }
    }

    internal static async Task RequireIdentityAsync(AuthDbContext db, DbTransaction transaction,
        string expectedIdentity, CancellationToken cancellationToken)
    {
        RequireTransaction(db, transaction);
        TransactionState state = States.GetValue(transaction, static _ => new());
        await state.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string current = await BindLiveTransactionAsync(db, transaction, state, cancellationToken).ConfigureAwait(false);
            if (current != expectedIdentity)
            {
                throw new InvalidOperationException("Auth admission owner transaction changed.");
            }
        }
        finally
        {
            state.Gate.Release();
        }
    }

    private static async Task<string> BindLiveTransactionAsync(AuthDbContext db, DbTransaction transaction,
        TransactionState state, CancellationToken cancellationToken)
    {
        try
        {
            RequireTransaction(db, transaction);
            await using DbCommand command = db.Database.GetDbConnection().CreateCommand();
            command.Transaction = transaction;
            command.CommandTimeout = 30;
            command.CommandText = "SELECT pg_catalog.pg_current_xact_id()::text || '/' || pg_catalog.pg_backend_pid()::text || '/' || EXTRACT(EPOCH FROM pg_catalog.pg_postmaster_start_time())::text";
            string? identity = (string?)await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            string[] parts = identity?.Split('/', 3) ?? [];
            if (parts.Length != 3 || !ulong.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out _) ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int backend) || backend <= 0 ||
                string.IsNullOrWhiteSpace(parts[2]) || identity!.Length > 256)
            {
                throw new InvalidOperationException("Auth admission transaction identity is unavailable.");
            }
            // Bind server transaction, backend and server lifetime too. A recycled provider
            // object or reconnected server must never inherit prior transaction lock ownership.
            if (state.ServerIdentity != identity)
            {
                state.ServerIdentity = identity;
                state.Held.Clear();
                state.DeviceRows.Clear();
                state.Poisoned = false;
            }
            if (state.Poisoned)
            {
                throw new InvalidOperationException("Auth admission lock outcome is unavailable; the owner must roll back.");
            }
            RequireTransaction(db, transaction);
            return identity!;
        }
        catch
        {
            state.Poisoned = true;
            throw;
        }
    }

    private sealed class TransactionState
    {
        internal SemaphoreSlim Gate { get; } = new(1, 1);
        internal Dictionary<AuthAdmissionLockKey, EfTransactionKeyLockMode> Held { get; } = [];
        internal HashSet<Guid> DeviceRows { get; } = [];
        internal string? ServerIdentity { get; set; }
        internal volatile bool Poisoned;
    }

    private static Guid RequireId(Guid value) => value != Guid.Empty ? value :
        throw new ArgumentException("Auth admission identity is required.", nameof(value));
}
