namespace Gma.Modules.Auth.Tests;

using System.Data;
using System.Data.Common;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Admission;
using Gma.Modules.Auth.Persistence.Remembered;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

/// <summary>Provider-free contract/key/change-detection tests. No fake transaction supplies a
/// positive admission, and these cases do not prove PostgreSQL lock cooperation or real Auth E2E.</summary>
public sealed class AuthTransactionAdmissionTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 1, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SharedAndExclusiveUsersHaveExactSubjectSessionKeysAndCanonicalOrder()
    {
        Guid member = Guid.Parse("00000000-0000-0000-0000-000000000001");
        Guid session = Guid.Parse("00000000-0000-0000-0000-000000000002");
        var subject = AuthAdmissionLockKey.Subject("global", member);
        var child = AuthAdmissionLockKey.Session("global", member, session);
        Assert.Equal("gma/auth/transaction-admission/v1/subject/[\"global\",\"00000000-0000-0000-0000-000000000001\",\"00000000-0000-0000-0000-000000000000\"]", subject.Resource);
        Assert.Equal("gma/auth/transaction-admission/v1/session/[\"global\",\"00000000-0000-0000-0000-000000000001\",\"00000000-0000-0000-0000-000000000002\"]", child.Resource);
        Assert.Equal(new[] { subject, child }, AuthAdmissionLockKey.Ordered([child, subject, child]));
        Assert.NotEqual(subject, AuthAdmissionLockKey.Subject("another", member));
        Assert.NotEqual(child, AuthAdmissionLockKey.Session("global", member, Guid.NewGuid()));
    }

    [Theory]
    [InlineData("subject")]
    [InlineData("session-member")]
    [InlineData("session-id")]
    public void EmptyLockIdentitiesDeny(string kind)
    {
        Assert.Throws<ArgumentException>(() => kind switch
        {
            "subject" => AuthAdmissionLockKey.Subject("global", Guid.Empty),
            "session-member" => AuthAdmissionLockKey.Session("global", Guid.Empty, Guid.NewGuid()),
            _ => AuthAdmissionLockKey.Session("global", Guid.NewGuid(), Guid.Empty),
        });
    }

    [Fact]
    public void ATransactionCannotAcquireAnEarlierIdentityAfterItsCurrentFence()
    {
        var a = AuthAdmissionLockKey.Subject("global", Guid.Parse("00000000-0000-0000-0000-000000000001"));
        var b = AuthAdmissionLockKey.Subject("global", Guid.Parse("00000000-0000-0000-0000-000000000002"));
        Dictionary<AuthAdmissionLockKey, EfTransactionKeyLockMode> held = new()
        {
            [b] = EfTransactionKeyLockMode.Shared,
        };
        Assert.Throws<InvalidOperationException>(() =>
            AuthAdmissionLockKey.ValidateNextAccess(held, [a], EfTransactionKeyLockMode.Shared));
    }

    [Fact]
    public void ATransactionCannotUpgradeSharedAdmissionToInvalidation()
    {
        var key = AuthAdmissionLockKey.Subject("global", Guid.NewGuid());
        Dictionary<AuthAdmissionLockKey, EfTransactionKeyLockMode> held = new()
        {
            [key] = EfTransactionKeyLockMode.Shared,
        };
        Assert.Throws<InvalidOperationException>(() =>
            AuthAdmissionLockKey.ValidateNextAccess(held, [key], EfTransactionKeyLockMode.Exclusive));
        AuthAdmissionLockKey.ValidateNextAccess(held, [key], EfTransactionKeyLockMode.Shared);
        held[key] = EfTransactionKeyLockMode.Exclusive;
        AuthAdmissionLockKey.ValidateNextAccess(held, [key], EfTransactionKeyLockMode.Shared);
    }

    [Theory]
    [InlineData("session")]
    [InlineData("proof")]
    public void InvalidationCannotRebindTheOriginalFinancialSubject(string entity)
    {
        using var f = new Fixture();
        if (entity == "session")
        {
            f.Db.Entry(Assert.Single(f.Member.Sessions)).Property("MemberId").CurrentValue = new MemberId(Guid.NewGuid());
        }
        else
        {
            f.Proof.MemberId = Guid.NewGuid();
        }
        Assert.Throws<InvalidOperationException>(() => AuthAdmissionWriteGuard.ChangedKeys(f.Db));
    }

    [Fact]
    public void ProofAndDeviceWritesRetainTheExistingParentDeviceRowLock()
    {
        using var f = new Fixture();
        f.Proof.RevokedAtUtc = Now;
        _ = AuthAdmissionWriteGuard.ChangedKeys(f.Db);
        Assert.Equal<Guid>([f.Device.Id], AuthAdmissionWriteGuard.ChangedDeviceIds(f.Db));
    }

    [Theory]
    [InlineData("disable")]
    [InlineData("bulk-revoke")]
    [InlineData("security-epoch")]
    [InlineData("password")]
    public void MemberInvalidationPathsRequireSubjectGuard(string operation)
    {
        using var f = new Fixture();
        switch (operation)
        {
            case "disable":
                Assert.True(f.Member.Disable("synthetic test", Guid.NewGuid(), Now).IsSuccess);
                break;
            case "bulk-revoke":
                Assert.True(f.Member.RevokeSessions(Guid.NewGuid(), Now).IsSuccess);
                break;
            case "security-epoch":
                f.Db.Entry(f.Member).Property(nameof(Member.SecurityEpoch)).CurrentValue = 2L;
                break;
            default:
                f.Db.Entry(f.Member).Property(nameof(Member.PasswordHash)).CurrentValue = "changed-synthetic-hash";
                break;
        }
        Assert.Contains(AuthAdmissionLockKey.Subject("global", f.Member.Id.Value), AuthAdmissionWriteGuard.ChangedKeys(f.Db));
    }

    [Fact]
    public void IndividualSignOutRequiresExactSubjectAndSessionGuards()
    {
        using var f = new Fixture();
        Assert.True(f.Member.SignOutSession(f.SessionId, Now).IsSuccess);
        var keys = AuthAdmissionWriteGuard.ChangedKeys(f.Db);
        Assert.Contains(AuthAdmissionLockKey.Subject("global", f.Member.Id.Value), keys);
        Assert.Contains(AuthAdmissionLockKey.Session("global", f.Member.Id.Value, f.SessionId.Value), keys);
    }

    [Theory]
    [InlineData("IsActive")]
    [InlineData("AbsoluteExpiresAtUtc")]
    [InlineData("RememberedBrowserDeviceId")]
    public void SessionInvalidationPropertiesUseTheSameGuards(string property)
    {
        using var f = new Fixture();
        var session = Assert.Single(f.Member.Sessions);
        f.Db.Entry(session).Property(property).CurrentValue = property switch
        {
            "IsActive" => false,
            "AbsoluteExpiresAtUtc" => Now.AddMinutes(-1),
            _ => Guid.NewGuid(),
        };
        var keys = AuthAdmissionWriteGuard.ChangedKeys(f.Db);
        Assert.Contains(AuthAdmissionLockKey.Subject("global", f.Member.Id.Value), keys);
        Assert.Contains(AuthAdmissionLockKey.Session("global", f.Member.Id.Value, f.SessionId.Value), keys);
    }

    [Fact]
    public void DeviceSwitchFencesBothOriginalAndReplacementSubjectsAndSessions()
    {
        using var f = new Fixture();
        Guid otherMember = Guid.NewGuid(), otherSession = Guid.NewGuid();
        f.Device.ActiveMemberId = otherMember;
        f.Device.ActiveSessionId = otherSession;
        var keys = AuthAdmissionWriteGuard.ChangedKeys(f.Db);
        Assert.Equal(4, keys.Length);
        Assert.Contains(AuthAdmissionLockKey.Subject("global", f.Member.Id.Value), keys);
        Assert.Contains(AuthAdmissionLockKey.Session("global", f.Member.Id.Value, f.SessionId.Value), keys);
        Assert.Contains(AuthAdmissionLockKey.Subject("global", otherMember), keys);
        Assert.Contains(AuthAdmissionLockKey.Session("global", otherMember, otherSession), keys);
    }

    [Theory]
    [InlineData("lock")]
    [InlineData("revoke")]
    [InlineData("generation")]
    [InlineData("idle-expiry")]
    public void DeviceInvalidationPathsRetainSubjectSessionCooperation(string change)
    {
        using var f = new Fixture();
        switch (change)
        {
            case "lock":
                f.Device.State = RememberedBrowserState.Locked;
                break;
            case "revoke":
                f.Device.RevokedAtUtc = Now;
                break;
            case "generation":
                f.Device.Generation++;
                break;
            default:
                f.Device.IdleExpiresAtUtc = Now.AddMinutes(-1);
                break;
        }
        Assert.Contains(AuthAdmissionLockKey.Subject("global", f.Member.Id.Value), AuthAdmissionWriteGuard.ChangedKeys(f.Db));
    }

    [Theory]
    [InlineData("revoke")]
    [InlineData("expiry")]
    [InlineData("epoch")]
    [InlineData("pepper-version")]
    public void RememberedProofInvalidationPathsFenceTheirSubject(string change)
    {
        using var f = new Fixture();
        switch (change)
        {
            case "revoke":
                f.Proof.RevokedAtUtc = Now;
                break;
            case "expiry":
                f.Proof.ExpiresAtUtc = Now.AddMinutes(-1);
                break;
            case "epoch":
                f.Proof.SecurityEpoch++;
                break;
            default:
                f.Proof.PepperVersion = "synthetic-v2";
                break;
        }
        Assert.Contains(AuthAdmissionLockKey.Subject("global", f.Member.Id.Value), AuthAdmissionWriteGuard.ChangedKeys(f.Db));
    }

    [Theory]
    [InlineData("member")]
    [InlineData("session")]
    [InlineData("device")]
    [InlineData("proof")]
    public void TrackedRemovalCannotBypassInvalidationGuards(string entity)
    {
        using var f = new Fixture();
        f.Db.Remove(entity switch
        {
            "member" => f.Member,
            "session" => Assert.Single(f.Member.Sessions),
            "device" => f.Device,
            _ => f.Proof,
        });
        Assert.Contains(AuthAdmissionLockKey.Subject("global", f.Member.Id.Value), AuthAdmissionWriteGuard.ChangedKeys(f.Db));
    }

    [Fact]
    public void PostgreSqlSynchronousInvalidationFailsBeforeOpeningAnyConnection()
    {
        using var f = new Fixture();
        using var db = new AuthDbContext(new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql("Host=127.0.0.1;Database=never_opened;Username=never_used").Options, new Scope());
        db.Attach(f.Member);
        Assert.True(f.Member.Disable("synthetic test", Guid.NewGuid(), Now).IsSuccess);
        Assert.Throws<InvalidOperationException>(() => db.SaveChanges());
        Assert.Equal(ConnectionState.Closed, db.Database.GetDbConnection().State);
    }

    [Theory]
    [InlineData("member")]
    [InlineData("session")]
    [InlineData("scope")]
    [InlineData("provider")]
    public async Task UnsupportedOrMissingAdmissionNeverReturnsPositiveFakeEvidence(string reason)
    {
        using var f = new Fixture();
        var request = new AuthTransactionAdmissionRequest(reason == "scope" ? " " : "global",
            reason == "member" ? Guid.Empty : f.Member.Id.Value, reason == "session" ? Guid.Empty : f.SessionId.Value);
        var service = new AuthTransactionAdmission(f.Db, new Clock(), Options.Create(new RememberedBrowserOptions()));
        await using var tx = new UnsupportedTransaction();
        Assert.Null(await service.TryAcquireAsync(request, tx));
        Assert.False(tx.Completed);
    }

    [Fact]
    public async Task AdmissionCancellationIsNotTurnedIntoPermissionOrAnUncertainCommit()
    {
        using var f = new Fixture();
        var service = new AuthTransactionAdmission(f.Db, new Clock(), Options.Create(new RememberedBrowserOptions()));
        await using var tx = new UnsupportedTransaction();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await service.TryAcquireAsync(new("global", f.Member.Id.Value, f.SessionId.Value), tx, new CancellationToken(true)));
        Assert.False(tx.Completed);
    }

    [Theory]
    [InlineData("Host=127.0.0.1;Port=5432;Database=auth", true)]
    [InlineData("Host=127.0.0.1;Port=5433;Database=auth", false)]
    [InlineData("Host=127.0.0.2;Port=5432;Database=auth", false)]
    [InlineData("Host=127.0.0.1;Port=5432;Database=other", false)]
    public void BorrowedDatabaseMustMatchConfiguredAuthTarget(string connectionString, bool expected)
    {
        using var configured = new NpgsqlConnection("Host=127.0.0.1;Port=5432;Database=auth");
        using var supplied = new NpgsqlConnection(connectionString);
        Assert.Equal(expected, AuthTransactionAdmission.SameDatabase(configured, supplied));
        Assert.Equal(ConnectionState.Closed, supplied.State);
    }

    [Fact]
    public void UnsupportedSocketPathsCannotBeEquatedByCaseInsensitiveHostComparison()
    {
        using var configured = new NpgsqlConnection("Host=/run/Auth;Database=auth");
        using var different = new NpgsqlConnection("Host=/run/auth;Database=auth");
        using var identical = new NpgsqlConnection("Host=/run/Auth;Database=auth");
        Assert.False(AuthTransactionAdmission.SameDatabase(configured, different));
        Assert.False(AuthTransactionAdmission.SameDatabase(configured, identical));
    }

    [Fact]
    public void DnsHostnamesRetainTheirCaseInsensitiveIdentity()
    {
        using var configured = new NpgsqlConnection("Host=Auth.Local;Database=auth");
        using var supplied = new NpgsqlConnection("Host=auth.local;Database=auth");
        Assert.True(AuthTransactionAdmission.SameDatabase(configured, supplied));
    }

    [Fact]
    public void AuthFactContractHasNoFinancialModuleDependency()
    {
        Assert.DoesNotContain(typeof(IAuthTransactionAdmission).Assembly.GetReferencedAssemblies(),
            name => name.Name?.Contains("Points", StringComparison.Ordinal) == true ||
                name.Name?.Contains("Ledger", StringComparison.Ordinal) == true);
    }

    private sealed class Fixture : IDisposable
    {
        internal AuthDbContext Db { get; } = new(new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options, new Scope());
        internal Member Member { get; }
        internal MemberSessionId SessionId { get; } = new(Guid.NewGuid());
        internal RememberedBrowserDevice Device { get; }
        internal RememberedAccountProof Proof { get; }
        internal Fixture()
        {
            this.Member = Member.Create(new(Guid.NewGuid()), "global", "synthetic@example.test", MemberUsernameType.Email,
                "synthetic-hash", new(Guid.NewGuid()), Guid.NewGuid(), Now).Value;
            _ = this.Member.StartSession(this.SessionId, "synthetic-refresh", Now.AddDays(1), Now,
                absoluteExpiresAtUtc: Now.AddDays(2)).Value;
            this.Device = new()
            {
                Id = Guid.NewGuid(),
                ScopeId = "global",
                CredentialHash = "synthetic-device",
                ActiveMemberId = this.Member.Id.Value,
                ActiveSessionId = this.SessionId.Value,
                State = RememberedBrowserState.Active,
                CreatedAtUtc = Now,
                ExpiresAtUtc = Now.AddDays(2),
                IdleExpiresAtUtc = Now.AddMinutes(5),
                PinDigits = 6,
                RestoreEpoch = 1,
            };
            this.Proof = new()
            {
                Id = Guid.NewGuid(),
                ScopeId = "global",
                DeviceId = this.Device.Id,
                MemberId = this.Member.Id.Value,
                OriginalSessionId = this.SessionId.Value,
                SecurityEpoch = 1,
                PinHash = "synthetic-pin",
                PepperVersion = "synthetic-v1",
                CreatedAtUtc = Now,
                AuthenticatedAtUtc = Now,
                ExpiresAtUtc = Now.AddDays(1),
            };
            this.Db.Members.Add(this.Member);
            this.Db.RememberedBrowserDevices.Add(this.Device);
            this.Db.RememberedAccountProofs.Add(this.Proof);
            this.Db.SaveChanges();
        }
        public void Dispose() => this.Db.Dispose();
    }

    private sealed class Scope : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => "global";
        public bool TryRestoreScope(string? scopeId) => scopeId == "global";
    }
    private sealed class Clock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
    }
    private sealed class UnsupportedTransaction : DbTransaction
    {
        internal bool Completed { get; private set; }
        public override IsolationLevel IsolationLevel => IsolationLevel.Unspecified;
        protected override DbConnection? DbConnection => null;
        public override void Commit() => this.Completed = true;
        public override void Rollback() => this.Completed = true;
    }
}
