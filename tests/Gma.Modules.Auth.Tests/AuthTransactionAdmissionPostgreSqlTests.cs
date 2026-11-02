namespace Gma.Modules.Auth.Tests;

using System.Data;
using System.Data.Common;
using System.Reflection;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Remembered;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

[CollectionDefinition("Owned Auth admission PostgreSQL", DisableParallelization = true)]
public sealed class OwnedAuthAdmissionCases
{
}

/// <summary>Uses only a separately guarded, owned synthetic database supplied by the harness.
/// Never starts Docker, discovers a server, reads application configuration, or grants access.
/// These are real module/database races, not assembled-host/login/browser acceptance.</summary>
[Collection("Owned Auth admission PostgreSQL")]
public sealed class AuthTransactionAdmissionPostgreSqlTests
{
    [OwnedAuthPostgreSqlTheory]
    [InlineData("sign-out")]
    [InlineData("disable")]
    [InlineData("bulk-revoke")]
    [InlineData("security-epoch")]
    [InlineData("device-lock")]
    [InlineData("device-switch")]
    [InlineData("proof-revoke")]
    [InlineData("proof-pepper")]
    public async Task AdmissionAndExistingInvalidationSerializeThroughTheOwnerCommit(string change)
    {
        await using var f = await Fixture.CreateAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var connection = await f.OpenAsync(timeout.Token);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var configured = f.Context();
        var service = f.Admission(configured);
        await using var fence = await service.TryAcquireAsync(f.Request, transaction, timeout.Token);
        Assert.NotNull(fence);
        var started = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task writer = f.InvalidateAsync(change, started, timeout.Token);
        bool ownerCompleted = false;
        try
        {
            int pid = await started.Task.WaitAsync(timeout.Token);
            await f.AssertWaitingOnOwnedAdvisoryLockAsync(pid, timeout.Token);
            Assert.False(writer.IsCompleted);
            Assert.True(await fence.RevalidateAsync(timeout.Token));
            await transaction.CommitAsync(timeout.Token);
            ownerCompleted = true;
            await writer.WaitAsync(timeout.Token);
            await using var afterConnection = await f.OpenAsync(timeout.Token);
            await using var after = await afterConnection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
            Assert.Null(await service.TryAcquireAsync(f.Request, after, timeout.Token));
        }
        finally
        {
            if (!ownerCompleted && transaction.Connection is not null)
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }
            timeout.Cancel();
            try
            {
                await writer.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    [OwnedAuthPostgreSqlFact]
    public async Task ACommittedRevocationWinsBeforeLaterAdmission()
    {
        await using var f = await Fixture.CreateAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var writeConnection = await f.OpenAsync(timeout.Token);
        await using var writeTransaction = await writeConnection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var writer = f.Context(writeConnection);
        await writer.Database.UseTransactionAsync(writeTransaction, timeout.Token);
        var member = await writer.Members.Include(value => value.Sessions)
            .SingleAsync(value => value.Id == new MemberId(f.Request.MemberId), timeout.Token);
        Assert.True(member.SignOutSession(new(f.Request.SessionId), f.Clock.UtcNow).IsSuccess);
        await writer.SaveChangesAsync(timeout.Token);
        await using var readConnection = await f.OpenAsync(timeout.Token);
        await using var readTransaction = await readConnection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var configured = f.Context();
        Task<IAuthTransactionAdmissionFence?> admission = f.Admission(configured)
            .TryAcquireAsync(f.Request, readTransaction, timeout.Token).AsTask();
        bool ownerCompleted = false;
        try
        {
            await f.AssertWaitingOnOwnedAdvisoryLockAsync(readConnection.ProcessID, timeout.Token);
            await writeTransaction.CommitAsync(timeout.Token);
            ownerCompleted = true;
            Assert.Null(await admission.WaitAsync(timeout.Token));
            Assert.Same(readConnection, readTransaction.Connection); // Rejected admission did not finish its owner.
        }
        finally
        {
            if (!ownerCompleted && writeTransaction.Connection is not null)
            {
                await writeTransaction.RollbackAsync(CancellationToken.None);
            }
            timeout.Cancel();
        }
    }

    [OwnedAuthPostgreSqlFact]
    public async Task DisposingTheReadFenceDoesNotReleaseTransactionLocksOrCompleteItsOwner()
    {
        await using var f = await Fixture.CreateAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var connection = await f.OpenAsync(timeout.Token);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var configured = f.Context();
        var fence = await f.Admission(configured).TryAcquireAsync(f.Request, transaction, timeout.Token);
        Assert.NotNull(fence);
        await fence.DisposeAsync();
        Assert.Same(connection, transaction.Connection);
        Assert.False(await fence.RevalidateAsync(timeout.Token));
        var started = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task writer = f.InvalidateAsync("sign-out", started, timeout.Token);
        bool ownerCompleted = false;
        try
        {
            await f.AssertWaitingOnOwnedAdvisoryLockAsync(await started.Task.WaitAsync(timeout.Token), timeout.Token);
            await transaction.RollbackAsync(timeout.Token);
            ownerCompleted = true;
            await writer.WaitAsync(timeout.Token);
        }
        finally
        {
            if (!ownerCompleted && transaction.Connection is not null)
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }
            timeout.Cancel();
            try
            {
                await writer.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    [OwnedAuthPostgreSqlTheory]
    [InlineData(IsolationLevel.RepeatableRead)]
    [InlineData(IsolationLevel.Serializable)]
    public async Task UnsupportedIsolationDeniesWithoutCompletingTheBorrowedTransaction(IsolationLevel isolation)
    {
        await using var f = await Fixture.CreateAsync();
        await using var connection = await f.OpenAsync(CancellationToken.None);
        await using var transaction = await connection.BeginTransactionAsync(isolation);
        await using var configured = f.Context();
        Assert.Null(await f.Admission(configured).TryAcquireAsync(f.Request, transaction));
        Assert.Same(connection, transaction.Connection);
    }

    [OwnedAuthPostgreSqlTheory]
    [InlineData("member")]
    [InlineData("session")]
    [InlineData("scope")]
    public async Task AValidSessionDoesNotAdmitAnotherSubjectSessionOrScope(string mismatch)
    {
        await using var f = await Fixture.CreateAsync();
        await using var connection = await f.OpenAsync(CancellationToken.None);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await using var configured = f.Context();
        var request = mismatch switch
        {
            "member" => f.Request with { MemberId = Guid.NewGuid() },
            "session" => f.Request with { SessionId = Guid.NewGuid() },
            _ => f.Request with { ScopeId = "another-synthetic-scope" },
        };
        Assert.Null(await f.Admission(configured).TryAcquireAsync(request, transaction));
    }

    [OwnedAuthPostgreSqlFact]
    public async Task ExpiryAndLostOwnerTransactionBothDenyRevalidation()
    {
        await using var f = await Fixture.CreateAsync();
        await using var connection = await f.OpenAsync(CancellationToken.None);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await using var configured = f.Context();
        await using var fence = await f.Admission(configured).TryAcquireAsync(f.Request, transaction);
        Assert.NotNull(fence);
        f.Clock.UtcNow = fence.Evidence.ValidUntilUtc;
        Assert.False(await fence.RevalidateAsync());
        f.Clock.UtcNow = fence.Evidence.ObservedAtUtc;
        await transaction.RollbackAsync();
        Assert.False(await fence.RevalidateAsync());
    }

    [OwnedAuthPostgreSqlFact]
    public async Task FailedOwnedCommitRetainsTrackedChangesAndRollsBackTheDatabase()
    {
        await using var f = await Fixture.CreateAsync();
        var interceptor = new RefuseFirstCommit();
        await using var writer = f.Context(interceptor: interceptor);
        var member = await writer.Members.SingleAsync(value => value.Id == new MemberId(f.Request.MemberId));
        Assert.True(member.Disable("synthetic commit refusal", Guid.NewGuid(), f.Clock.UtcNow).IsSuccess);
        await Assert.ThrowsAsync<CommitRefusedException>(() => writer.SaveChangesAsync());
        Assert.Equal(EntityState.Modified, writer.Entry(member).State);
        await using (var read = f.Context())
        {
            Assert.Equal(Gma.Modules.Auth.Domain.Enums.MemberStatus.Active, (await read.Members.SingleAsync(value => value.Id == member.Id)).Status);
        }
        await writer.SaveChangesAsync();
        Assert.Equal(EntityState.Unchanged, writer.Entry(member).State);
    }

    [OwnedAuthPostgreSqlFact]
    public async Task AnotherSubjectCannotBeAddedAfterASessionFenceAcrossBorrowedContexts()
    {
        await using var f = await Fixture.CreateAsync();
        var another = await f.SeedAnotherSubjectAsync();
        await using var connection = await f.OpenAsync(CancellationToken.None);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await using var configured = f.Context();
        await using var fence = await f.Admission(configured).TryAcquireAsync(f.Request, transaction);
        Assert.NotNull(fence);
        await using var secondContext = f.Context();
        Assert.Null(await f.Admission(secondContext).TryAcquireAsync(another, transaction));
        Assert.True(await fence.RevalidateAsync());
    }

    [OwnedAuthPostgreSqlFact]
    public async Task AnAuthWriterCannotUpgradeAnAlreadyHeldSharedAdmission()
    {
        await using var f = await Fixture.CreateAsync();
        await using var connection = await f.OpenAsync(CancellationToken.None);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await using var configured = f.Context();
        await using var fence = await f.Admission(configured).TryAcquireAsync(f.Request, transaction);
        Assert.NotNull(fence);
        await using var writer = f.Context(connection);
        await writer.Database.UseTransactionAsync(transaction);
        var member = await writer.Members.Include(value => value.Sessions)
            .SingleAsync(value => value.Id == new MemberId(f.Request.MemberId));
        Assert.True(member.Disable("unsupported same-transaction upgrade", Guid.NewGuid(), f.Clock.UtcNow).IsSuccess);
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.SaveChangesAsync());
        await transaction.RollbackAsync();
    }

    [OwnedAuthPostgreSqlFact]
    public async Task ANewLogicalTransactionCannotInheritPriorLocksOrValidateItsOldFence()
    {
        await using var f = await Fixture.CreateAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var connection = await f.OpenAsync(timeout.Token);
        await using var configured = f.Context();
        var first = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        var oldFence = await f.Admission(configured).TryAcquireAsync(f.Request, first, timeout.Token);
        Assert.NotNull(oldFence);
        await first.CommitAsync(timeout.Token);
        await first.DisposeAsync();
        await using var next = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var fence = await f.Admission(configured).TryAcquireAsync(f.Request, next, timeout.Token);
        Assert.NotNull(fence);
        Assert.False(await oldFence.RevalidateAsync(timeout.Token));
        await oldFence.DisposeAsync();
        Assert.Same(connection, next.Connection);
        var started = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task writer = f.InvalidateAsync("sign-out", started, timeout.Token);
        bool ownerCompleted = false;
        try
        {
            await f.AssertWaitingOnOwnedAdvisoryLockAsync(await started.Task.WaitAsync(timeout.Token), timeout.Token);
            Assert.True(await fence.RevalidateAsync(timeout.Token));
            await next.RollbackAsync(timeout.Token);
            ownerCompleted = true;
            await writer.WaitAsync(timeout.Token);
        }
        finally
        {
            if (!ownerCompleted && next.Connection is not null)
            {
                await next.RollbackAsync(CancellationToken.None);
            }
            timeout.Cancel();
            try
            {
                await writer.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    [OwnedAuthPostgreSqlFact]
    public async Task TransactionLocalFormattingChangesCannotResetHeldAdmissionOrPermitAnUpgrade()
    {
        await using var f = await Fixture.CreateAsync();
        await using var connection = await f.OpenAsync(CancellationToken.None);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await using var configured = f.Context();
        await using var fence = await f.Admission(configured).TryAcquireAsync(f.Request, transaction);
        Assert.NotNull(fence);
        // Formatting only, confined to this externally owned synthetic transaction and undone
        // by rollback. No server, account, security or operating-system setting is changed.
        await using (var command = new NpgsqlCommand("SET LOCAL TIME ZONE 'Pacific/Auckland'", connection, transaction))
        {
            await command.ExecuteNonQueryAsync();
        }
        await using (var command = new NpgsqlCommand("SET LOCAL DateStyle = 'SQL, DMY'", connection, transaction))
        {
            await command.ExecuteNonQueryAsync();
        }
        Assert.True(await fence.RevalidateAsync());
        await using var writer = f.Context(connection);
        await writer.Database.UseTransactionAsync(transaction);
        var member = await writer.Members.Include(value => value.Sessions)
            .SingleAsync(value => value.Id == new MemberId(f.Request.MemberId));
        Assert.True(member.Disable("unsupported upgrade after formatting change", Guid.NewGuid(), f.Clock.UtcNow).IsSuccess);
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.SaveChangesAsync());
        await transaction.RollbackAsync();
    }

    [OwnedAuthPostgreSqlTheory]
    [InlineData("session")]
    [InlineData("proof")]
    [InlineData("device")]
    public async Task RawRetentionCannotDeleteAnAdmissionInputBeforeItsOwnerCompletes(string category)
    {
        await using var f = await Fixture.CreateAsync();
        await f.MakeFirstRetentionCandidateAsync(category);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var connection = await f.OpenAsync(timeout.Token);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var configured = f.Context();
        await using var fence = await f.Admission(configured).TryAcquireAsync(f.Request, transaction, timeout.Token);
        Assert.NotNull(fence);
        var started = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int> retention = f.RetainAsync(category, started, timeout.Token);
        bool ownerCompleted = false;
        try
        {
            await f.AssertWaitingOnOwnedAdvisoryLockAsync(await started.Task.WaitAsync(timeout.Token), timeout.Token);
            Assert.True(await fence.RevalidateAsync(timeout.Token));
            await transaction.CommitAsync(timeout.Token);
            ownerCompleted = true;
            Assert.Equal(1, await retention.WaitAsync(timeout.Token));
            await using var afterConnection = await f.OpenAsync(timeout.Token);
            await using var after = await afterConnection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
            Assert.Null(await f.Admission(configured).TryAcquireAsync(f.Request, after, timeout.Token));
        }
        finally
        {
            if (!ownerCompleted && transaction.Connection is not null)
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }
            timeout.Cancel();
            try
            {
                await retention.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    [OwnedAuthPostgreSqlFact]
    public async Task DeviceRetentionWaitsForTheExistingDeviceRowBeforeTakingAdmissionKeys()
    {
        await using var f = await Fixture.CreateAsync();
        await f.MakeFirstRetentionCandidateAsync("device");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var connection = await f.OpenAsync(timeout.Token);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var configured = f.Context();
        await using var fence = await f.Admission(configured).TryAcquireAsync(f.Request, transaction, timeout.Token);
        Assert.NotNull(fence);
        var writerStarted = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var retentionStarted = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task writer = f.InvalidateAsync("device-lock", writerStarted, timeout.Token);
        Task<int>? retention = null;
        bool ownerCompleted = false;
        try
        {
            await f.AssertWaitingOnOwnedAdvisoryLockAsync(await writerStarted.Task.WaitAsync(timeout.Token), timeout.Token);
            retention = f.RetainAsync("device", retentionStarted, timeout.Token);
            await f.AssertWaitingOnOwnedNonAdvisoryLockAsync(await retentionStarted.Task.WaitAsync(timeout.Token), timeout.Token);
            await transaction.CommitAsync(timeout.Token);
            ownerCompleted = true;
            await writer.WaitAsync(timeout.Token);
            Assert.Equal(1, await retention.WaitAsync(timeout.Token));
        }
        finally
        {
            if (!ownerCompleted && transaction.Connection is not null)
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }
            timeout.Cancel();
            try
            {
                await writer.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
            }
            if (retention is not null)
            {
                try
                {
                    await retention.WaitAsync(TimeSpan.FromSeconds(5));
                }
                catch (OperationCanceledException)
                {
                }
            }
        }
    }

    [OwnedAuthPostgreSqlTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StaleDeviceWritesFenceThePersistedActiveSubjectEvenWhenTheTrackedDeviceWasUnbound(bool unbound)
    {
        await using var f = await Fixture.CreateAsync();
        if (unbound)
        {
            await f.UnbindDeviceAsync();
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var staleConnection = await f.OpenAsync(timeout.Token);
        await using var stale = f.Context(staleConnection);
        var device = await stale.RememberedBrowserDevices.SingleAsync(value => value.Id == f.DeviceId, timeout.Token);
        var currentRequest = await f.SwitchDeviceToAnotherSubjectWithoutChangingStampAsync();
        await using var connection = await f.OpenAsync(timeout.Token);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
        await using var configured = f.Context();
        await using var fence = await f.Admission(configured).TryAcquireAsync(currentRequest, transaction, timeout.Token);
        Assert.NotNull(fence);
        device.RevokedAtUtc = f.Clock.UtcNow;
        Task writer = stale.SaveChangesAsync(timeout.Token);
        bool ownerCompleted = false;
        try
        {
            await f.AssertWaitingOnOwnedAdvisoryLockAsync(staleConnection.ProcessID, timeout.Token);
            Assert.True(await fence.RevalidateAsync(timeout.Token));
            await transaction.CommitAsync(timeout.Token);
            ownerCompleted = true;
            await writer.WaitAsync(timeout.Token);
            await using var afterConnection = await f.OpenAsync(timeout.Token);
            await using var after = await afterConnection.BeginTransactionAsync(IsolationLevel.ReadCommitted, timeout.Token);
            Assert.Null(await f.Admission(configured).TryAcquireAsync(currentRequest, after, timeout.Token));
        }
        finally
        {
            if (!ownerCompleted && transaction.Connection is not null)
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }
            timeout.Cancel();
            try
            {
                await writer.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private sealed class CommitRefusedException : Exception
    {
    }
    private sealed class RefuseFirstCommit : DbTransactionInterceptor
    {
        private bool refused;
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,
            TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (!this.refused)
            {
                this.refused = true;
                throw new CommitRefusedException();
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly string connectionString;
        private readonly RememberedBrowserOptions remembered = new()
        {
            Enabled = true,
            RestoreEpoch = 1,
            PepperVersion = "synthetic-v1",
            Pepper = Convert.ToBase64String(new byte[32]),
        };
        internal MutableClock Clock { get; } = new();
        internal AuthTransactionAdmissionRequest Request { get; }
        private readonly Guid deviceId = Guid.NewGuid();
        private readonly Guid proofId = Guid.NewGuid();
        internal Guid DeviceId => this.deviceId;

        private Fixture(string connectionString)
        {
            this.connectionString = connectionString;
            this.Request = new("auth-fence-" + Guid.NewGuid().ToString("N"), Guid.NewGuid(), Guid.NewGuid());
        }

        internal static async Task<Fixture> CreateAsync()
        {
            string value = Environment.GetEnvironmentVariable("GMA_AUTH_ADMISSION_PG_CONNECTION") ??
                throw new InvalidOperationException("Owned Auth PostgreSQL connection is required.");
            string owner = Environment.GetEnvironmentVariable("GMA_AUTH_ADMISSION_PG_OWNER") ?? string.Empty;
            var builder = new NpgsqlConnectionStringBuilder(value)
            {
                Pooling = false,
                Timeout = 5,
                CommandTimeout = 5,
            };
            const string databasePrefix = "gma_auth_admission_";
            string database = builder.Database ?? string.Empty;
            if (builder.Host != "127.0.0.1" || !Guid.TryParseExact(owner, "D", out Guid ownerId) ||
                !database.StartsWith(databasePrefix, StringComparison.Ordinal) || database.Length != databasePrefix.Length + 32 ||
                !database.Skip(databasePrefix.Length).All(value => value is (>= 'a' and <= 'f') or (>= '0' and <= '9')))
            {
                throw new InvalidOperationException("Only the exact owned loopback synthetic database is supported.");
            }
            var fixture = new Fixture(builder.ConnectionString);
            await using var connection = await fixture.OpenAsync(CancellationToken.None);
            await using (var command = new NpgsqlCommand("SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = current_database()", connection))
            {
                Assert.Equal("gma-auth-admission-owner:" + ownerId.ToString("D"), (string?)await command.ExecuteScalarAsync());
            }
            await using var db = fixture.Context();
            await db.Database.MigrateAsync();
            var member = Member.Create(new(fixture.Request.MemberId), fixture.Request.ScopeId, "synthetic@example.test",
                MemberUsernameType.Email, "synthetic-password-hash", new(Guid.NewGuid()), Guid.NewGuid(), fixture.Clock.UtcNow).Value;
            var session = member.StartSession(new(fixture.Request.SessionId), "synthetic-refresh-hash",
                fixture.Clock.UtcNow.AddMinutes(30), fixture.Clock.UtcNow,
                absoluteExpiresAtUtc: fixture.Clock.UtcNow.AddHours(1)).Value;
            session.BindRememberedBrowser(fixture.deviceId, fixture.proofId, 1, member.SecurityEpoch);
            db.Members.Add(member);
            db.RememberedBrowserDevices.Add(new()
            {
                Id = fixture.deviceId,
                ScopeId = fixture.Request.ScopeId,
                CredentialHash = new string('a', 32) + Guid.NewGuid().ToString("N"),
                Generation = 1,
                RestoreEpoch = 1,
                State = RememberedBrowserState.Active,
                PinDigits = 6,
                ActiveMemberId = fixture.Request.MemberId,
                ActiveSessionId = fixture.Request.SessionId,
                ActiveProofId = fixture.proofId,
                CreatedAtUtc = fixture.Clock.UtcNow,
                ExpiresAtUtc = fixture.Clock.UtcNow.AddMinutes(30),
                IdleExpiresAtUtc = fixture.Clock.UtcNow.AddMinutes(5),
            });
            db.RememberedAccountProofs.Add(new()
            {
                Id = fixture.proofId,
                ScopeId = fixture.Request.ScopeId,
                DeviceId = fixture.deviceId,
                MemberId = fixture.Request.MemberId,
                OriginalSessionId = fixture.Request.SessionId,
                SecurityEpoch = member.SecurityEpoch,
                PinHash = "synthetic-pin-hash",
                PepperVersion = "synthetic-v1",
                CreatedAtUtc = fixture.Clock.UtcNow,
                AuthenticatedAtUtc = fixture.Clock.UtcNow,
                ExpiresAtUtc = fixture.Clock.UtcNow.AddMinutes(30),
            });
            await db.SaveChangesAsync();
            return fixture;
        }

        internal AuthDbContext Context(NpgsqlConnection? connection = null, IInterceptor? interceptor = null)
        {
            var builder = new DbContextOptionsBuilder<AuthDbContext>();
            if (connection is null)
            {
                builder.UseNpgsql(this.connectionString, options => options
                    .MigrationsAssembly(AuthMigrations.PostgreSqlAssembly).MigrationsHistoryTable(AuthMigrations.HistoryTable, AuthMigrations.Schema));
            }
            else
            {
                builder.UseNpgsql(connection, contextOwnsConnection: false, npgsqlOptionsAction: options => options
                    .MigrationsAssembly(AuthMigrations.PostgreSqlAssembly).MigrationsHistoryTable(AuthMigrations.HistoryTable, AuthMigrations.Schema));
            }
            if (interceptor is not null)
            {
                builder.AddInterceptors(interceptor);
            }
            return new(builder.Options, new Scope(this.Request.ScopeId));
        }

        internal global::Gma.Modules.Auth.Persistence.Admission.AuthTransactionAdmission Admission(AuthDbContext configured) =>
            new(configured, this.Clock, Options.Create(this.remembered));

        internal async Task<NpgsqlConnection> OpenAsync(CancellationToken cancellationToken)
        {
            var connection = new NpgsqlConnection(this.connectionString);
            try
            {
                await connection.OpenAsync(cancellationToken);
                return connection;
            }
            catch
            {
                await connection.DisposeAsync();
                throw;
            }
        }

        internal async Task InvalidateAsync(string change, TaskCompletionSource<int> started, CancellationToken cancellationToken)
        {
            try
            {
                await using var connection = await this.OpenAsync(cancellationToken);
                await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
                await using var db = this.Context(connection);
                await db.Database.UseTransactionAsync(transaction, cancellationToken);
                var member = await db.Members.Include(value => value.Sessions)
                    .SingleAsync(value => value.Id == new MemberId(this.Request.MemberId), cancellationToken);
                switch (change)
                {
                    case "sign-out":
                        Assert.True(member.SignOutSession(new(this.Request.SessionId), this.Clock.UtcNow).IsSuccess);
                        break;
                    case "disable":
                        Assert.True(member.Disable("synthetic test", Guid.NewGuid(), this.Clock.UtcNow).IsSuccess);
                        break;
                    case "bulk-revoke":
                        Assert.True(member.RevokeSessions(Guid.NewGuid(), this.Clock.UtcNow).IsSuccess);
                        break;
                    case "security-epoch":
                        db.Entry(member).Property(nameof(Member.SecurityEpoch)).CurrentValue = member.SecurityEpoch + 1;
                        break;
                    case "device-lock":
                    case "device-switch":
                        var device = await db.RememberedBrowserDevices.SingleAsync(value => value.Id == this.deviceId, cancellationToken);
                        if (change == "device-lock")
                        {
                            device.State = RememberedBrowserState.Locked;
                        }
                        else
                        {
                            device.ActiveMemberId = Guid.NewGuid();
                            device.ActiveSessionId = Guid.NewGuid();
                            device.Touch();
                        }
                        break;
                    default:
                        var proof = await db.RememberedAccountProofs.SingleAsync(value => value.Id == this.proofId, cancellationToken);
                        if (change == "proof-revoke")
                        {
                            proof.RevokedAtUtc = this.Clock.UtcNow;
                        }
                        else
                        {
                            proof.PepperVersion = "synthetic-v2";
                        }
                        break;
                }
                started.TrySetResult(connection.ProcessID);
                await db.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch (Exception error)
            {
                started.TrySetException(error);
                throw;
            }
        }

        internal async Task<AuthTransactionAdmissionRequest> SeedAnotherSubjectAsync()
        {
            var request = this.Request with { MemberId = Guid.NewGuid(), SessionId = Guid.NewGuid() };
            await using var db = this.Context();
            var member = Member.Create(new(request.MemberId), request.ScopeId, "synthetic-" + request.MemberId.ToString("N") + "@example.test",
                MemberUsernameType.Email, "synthetic-password", new(Guid.NewGuid()), Guid.NewGuid(), this.Clock.UtcNow).Value;
            _ = member.StartSession(new(request.SessionId), "synthetic-refresh", this.Clock.UtcNow.AddMinutes(30),
                this.Clock.UtcNow, absoluteExpiresAtUtc: this.Clock.UtcNow.AddHours(1)).Value;
            db.Members.Add(member);
            await db.SaveChangesAsync();
            return request;
        }

        internal async Task UnbindDeviceAsync()
        {
            await using var db = this.Context();
            var device = await db.RememberedBrowserDevices.SingleAsync(value => value.Id == this.deviceId);
            device.ActiveMemberId = null;
            device.ActiveSessionId = null;
            device.ActiveProofId = null;
            device.State = RememberedBrowserState.Locked;
            await db.SaveChangesAsync();
        }

        internal async Task<AuthTransactionAdmissionRequest> SwitchDeviceToAnotherSubjectWithoutChangingStampAsync()
        {
            var request = this.Request with { MemberId = Guid.NewGuid(), SessionId = Guid.NewGuid() };
            await using var db = this.Context();
            var member = Member.Create(new(request.MemberId), request.ScopeId, "synthetic-" + request.MemberId.ToString("N") + "@example.test",
                MemberUsernameType.Email, "synthetic-password", new(Guid.NewGuid()), Guid.NewGuid(), this.Clock.UtcNow).Value;
            var session = member.StartSession(new(request.SessionId), "synthetic-refresh", this.Clock.UtcNow.AddMinutes(30),
                this.Clock.UtcNow, absoluteExpiresAtUtc: this.Clock.UtcNow.AddHours(1)).Value;
            session.BindRememberedBrowser(this.deviceId, null, 1, member.SecurityEpoch);
            db.Members.Add(member);
            var device = await db.RememberedBrowserDevices.SingleAsync(value => value.Id == this.deviceId);
            device.ActiveMemberId = request.MemberId;
            device.ActiveSessionId = request.SessionId;
            device.ActiveProofId = null;
            device.State = RememberedBrowserState.Active;
            // Deliberately leave the stamp unchanged: the admission guarantee must not depend
            // on every caller remembering Touch(), or on stale original owner/session values.
            await db.SaveChangesAsync();
            return request;
        }

        internal async Task MakeFirstRetentionCandidateAsync(string category)
        {
            await using var db = this.Context();
            DateTimeOffset expiry = this.Clock.UtcNow.AddSeconds(1);
            if (category == "session")
            {
                var session = await db.MemberSessions.SingleAsync(value => value.Id == new MemberSessionId(this.Request.SessionId));
                db.Entry(session).Property(nameof(session.RefreshTokenExpiresAtUtc)).CurrentValue = expiry;
            }
            else if (category == "proof")
            {
                (await db.RememberedAccountProofs.SingleAsync(value => value.Id == this.proofId)).ExpiresAtUtc = expiry;
            }
            else
            {
                var device = await db.RememberedBrowserDevices.SingleAsync(value => value.Id == this.deviceId);
                device.ExpiresAtUtc = expiry;
                device.Touch();
            }
            await db.SaveChangesAsync();
        }

        internal async Task<int> RetainAsync(string category, TaskCompletionSource<int> started, CancellationToken cancellationToken)
        {
            try
            {
                await using var connection = await this.OpenAsync(cancellationToken);
                await using var db = this.Context(connection);
                string method = category switch
                {
                    "session" => "DeleteExpiredSessionsBatchAsync",
                    "proof" => "DeleteExpiredRememberedProofsBatchAsync",
                    _ => "DeleteExpiredRememberedDevicesBatchAsync",
                };
                var implementation = typeof(AuthRetentionService).GetMethod(method, BindingFlags.NonPublic | BindingFlags.Static)!;
                started.TrySetResult(connection.ProcessID);
                return await (Task<int>)implementation.Invoke(null, [db, this.Clock.UtcNow.AddSeconds(2), 1, cancellationToken])!;
            }
            catch (Exception error)
            {
                started.TrySetException(error);
                throw;
            }
        }

        internal async Task AssertWaitingOnOwnedAdvisoryLockAsync(int backendPid, CancellationToken cancellationToken)
            => await this.AssertWaitingAsync(backendPid, true, cancellationToken);

        internal async Task AssertWaitingOnOwnedNonAdvisoryLockAsync(int backendPid, CancellationToken cancellationToken)
            => await this.AssertWaitingAsync(backendPid, false, cancellationToken);

        private async Task AssertWaitingAsync(int backendPid, bool advisory, CancellationToken cancellationToken)
        {
            await using var probe = await this.OpenAsync(cancellationToken);
            await using var command = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = @pid AND (locktype = 'advisory') = @advisory AND NOT granted)", probe);
            command.Parameters.AddWithValue("pid", backendPid);
            command.Parameters.AddWithValue("advisory", advisory);
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(TimeSpan.FromSeconds(5));
            while (!(bool)(await command.ExecuteScalarAsync(bounded.Token))!)
            {
                await Task.Delay(20, bounded.Token);
            }
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask; // Whole owned DB is removed by the external harness.
    }

    private sealed class Scope(string scope) : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => scope;
        public bool TryRestoreScope(string? scopeId) => scopeId == scope;
    }
    private sealed class MutableClock : ISystemClock
    {
        public DateTimeOffset UtcNow { get; set; } = DateTimeOffset.UtcNow;
    }
}

public sealed class OwnedAuthPostgreSqlFactAttribute : FactAttribute
{
    public OwnedAuthPostgreSqlFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("GMA_AUTH_ADMISSION_PG_CONNECTION") is null)
        {
            this.Skip = "Requires the separately guarded owned synthetic PostgreSQL harness.";
        }
    }
}
public sealed class OwnedAuthPostgreSqlTheoryAttribute : TheoryAttribute
{
    public OwnedAuthPostgreSqlTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("GMA_AUTH_ADMISSION_PG_CONNECTION") is null)
        {
            this.Skip = "Requires the separately guarded owned synthetic PostgreSQL harness.";
        }
    }
}
