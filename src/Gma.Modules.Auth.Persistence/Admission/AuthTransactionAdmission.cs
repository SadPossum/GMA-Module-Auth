namespace Gma.Modules.Auth.Persistence.Admission;

using System.Data;
using System.Data.Common;
using Gma.Framework.Naming;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;

internal sealed class AuthTransactionAdmission(AuthDbContext configured, ISystemClock clock,
    IOptions<RememberedBrowserOptions> options) : IAuthTransactionAdmission
{
    public async ValueTask<IAuthTransactionAdmissionFence?> TryAcquireAsync(AuthTransactionAdmissionRequest request,
        DbTransaction ownerTransaction, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AuthDbContext? borrowed = null;
        try
        {
            if (request is null || request.MemberId == Guid.Empty || request.SessionId == Guid.Empty ||
                !ScopeIds.TryNormalize(request.ScopeId, out string? scope) || request.ScopeId != scope ||
                !configured.Database.IsNpgsql() || configured.ChangeTracker.HasChanges() ||
                (configured.ScopeFilterEnabled && configured.CurrentScopeId != scope) ||
                ownerTransaction is not NpgsqlTransaction ||
                ownerTransaction.Connection is not NpgsqlConnection connection ||
                connection.State != ConnectionState.Open || ownerTransaction.IsolationLevel != IsolationLevel.ReadCommitted ||
                System.Transactions.Transaction.Current is not null ||
                !SameDatabase(configured.Database.GetDbConnection(), connection))
            {
                return null;
            }

            borrowed = new AuthDbContext(new DbContextOptionsBuilder<AuthDbContext>()
                .UseNpgsql(connection, contextOwnsConnection: false).Options, new ReadScope(scope));
            await borrowed.Database.UseTransactionAsync(ownerTransaction, cancellationToken).ConfigureAwait(false);
            AuthAdmissionLockKey.RequireTransaction(borrowed, ownerTransaction);
            string ownerIdentity = await AuthAdmissionLockKey.AcquireAsync(borrowed,
                [AuthAdmissionLockKey.Subject(scope, request.MemberId), AuthAdmissionLockKey.Session(scope, request.MemberId, request.SessionId)],
                EfTransactionKeyLockMode.Shared, cancellationToken).ConfigureAwait(false);

            RememberedConfiguration configuration = RememberedConfiguration.Read(options.Value);
            DateTimeOffset now = clock.UtcNow;
            var reader = new AuthSessionAdmissionReader(borrowed, clock, Options.Create(configuration.ToOptions()));
            if (await new AuthMemberAdmissionReader(borrowed).FindActiveAsync(scope, request.MemberId, cancellationToken)
                    .ConfigureAwait(false) is null ||
                !await reader.IsActiveAsync(scope, request.MemberId, request.SessionId, cancellationToken).ConfigureAwait(false))
            {
                return null;
            }

            DateTimeOffset? until = await FindValidityAsync(borrowed, request, cancellationToken).ConfigureAwait(false);
            if (until is null || until <= now || now.Offset != TimeSpan.Zero)
            {
                return null;
            }
            var evidence = new AuthTransactionAdmissionEvidence(request, now, until.Value);
            var fence = new Fence(borrowed, ownerTransaction, ownerIdentity, evidence, configuration, clock, options);
            if (!await fence.RevalidateAsync(cancellationToken).ConfigureAwait(false))
            {
                return null;
            }
            borrowed = null; // Transfer only this read context to the fence, never the transaction.
            return fence;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            if (borrowed is not null)
            {
                await borrowed.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    internal static bool SameDatabase(DbConnection expected, NpgsqlConnection supplied)
    {
        if (expected is not NpgsqlConnection)
        {
            return false;
        }
        var left = new NpgsqlConnectionStringBuilder(expected.ConnectionString);
        var right = new NpgsqlConnectionStringBuilder(supplied.ConnectionString);
        return !string.IsNullOrWhiteSpace(left.Database) && !string.IsNullOrWhiteSpace(left.Host) &&
            !string.IsNullOrWhiteSpace(right.Host) && !left.Host.Contains(',') && !right.Host.Contains(',') &&
            left.Host.IndexOfAny(['/', '\\']) < 0 && right.Host.IndexOfAny(['/', '\\']) < 0 &&
            string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) && left.Port == right.Port &&
            string.Equals(left.Database, right.Database, StringComparison.Ordinal);
    }

    private static async Task<DateTimeOffset?> FindValidityAsync(AuthDbContext db,
        AuthTransactionAdmissionRequest request, CancellationToken cancellationToken)
    {
        MemberSessionId sessionId = new(request.SessionId);
        var session = await db.MemberSessions.IgnoreQueryFilters().AsNoTracking()
            .SingleOrDefaultAsync(value => value.ScopeId == request.ScopeId && value.Id == sessionId &&
                value.MemberId == new MemberId(request.MemberId), cancellationToken).ConfigureAwait(false);
        if (session is null)
        {
            return null;
        }
        DateTimeOffset until = session.AbsoluteExpiresAtUtc;
        if (session.RememberedBrowserDeviceId is Guid deviceId)
        {
            var device = await db.RememberedBrowserDevices.IgnoreQueryFilters().AsNoTracking()
                .SingleOrDefaultAsync(value => value.ScopeId == request.ScopeId && value.Id == deviceId,
                    cancellationToken).ConfigureAwait(false);
            if (device is null || device.IdleExpiresAtUtc is null)
            {
                return null;
            }
            until = Min(until, Min(device.ExpiresAtUtc, device.IdleExpiresAtUtc.Value));
            if (device.ActiveProofId is Guid proofId)
            {
                var proof = await db.RememberedAccountProofs.IgnoreQueryFilters().AsNoTracking()
                    .SingleOrDefaultAsync(value => value.ScopeId == request.ScopeId && value.Id == proofId,
                        cancellationToken).ConfigureAwait(false);
                if (proof is null)
                {
                    return null;
                }
                until = Min(until, proof.ExpiresAtUtc);
            }
        }
        return until;
    }

    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;

    private sealed class ReadScope(string scope) : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => scope;
        public bool TryRestoreScope(string? scopeId) => scopeId == scope;
    }

    private sealed record RememberedConfiguration(bool Enabled, long RestoreEpoch, string PepperVersion)
    {
        internal static RememberedConfiguration Read(RememberedBrowserOptions value) =>
            new(value.Enabled, value.RestoreEpoch, value.PepperVersion);
        internal RememberedBrowserOptions ToOptions() => new()
        {
            Enabled = this.Enabled,
            RestoreEpoch = this.RestoreEpoch,
            PepperVersion = this.PepperVersion,
        };
    }

    private sealed class Fence(AuthDbContext db, DbTransaction transaction, string ownerIdentity,
        AuthTransactionAdmissionEvidence evidence, RememberedConfiguration configuration,
        ISystemClock clock, IOptions<RememberedBrowserOptions> currentOptions) : IAuthTransactionAdmissionFence
    {
        private bool disposed;
        public AuthTransactionAdmissionEvidence Evidence => evidence;

        public async ValueTask<bool> RevalidateAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (this.disposed || configuration != RememberedConfiguration.Read(currentOptions.Value) ||
                    clock.UtcNow < evidence.ObservedAtUtc || clock.UtcNow >= evidence.ValidUntilUtc)
                {
                    return false;
                }
                await AuthAdmissionLockKey.RequireIdentityAsync(db, transaction, ownerIdentity, cancellationToken).ConfigureAwait(false);
                if (db.ChangeTracker.HasChanges())
                {
                    return false;
                }
                var request = evidence.Request;
                var member = await new AuthMemberAdmissionReader(db)
                    .FindActiveAsync(request.ScopeId, request.MemberId, cancellationToken).ConfigureAwait(false);
                if (member is null)
                {
                    return false;
                }
                bool active = await new AuthSessionAdmissionReader(db, clock, Options.Create(configuration.ToOptions()))
                    .IsActiveAsync(request.ScopeId, request.MemberId, request.SessionId, cancellationToken).ConfigureAwait(false);
                await AuthAdmissionLockKey.RequireIdentityAsync(db, transaction, ownerIdentity, cancellationToken).ConfigureAwait(false);
                return active && clock.UtcNow >= evidence.ObservedAtUtc && clock.UtcNow < evidence.ValidUntilUtc &&
                    configuration == RememberedConfiguration.Read(currentOptions.Value);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (this.disposed)
            {
                return;
            }
            this.disposed = true;
            await db.DisposeAsync().ConfigureAwait(false);
        }
    }
}
