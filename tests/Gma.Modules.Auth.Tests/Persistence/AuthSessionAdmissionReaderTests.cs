namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Runtime.Time;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Xunit;
using DomainMemberUsernameType = Gma.Modules.Auth.Domain.Enums.MemberUsernameType;

[Trait("Category", "Unit")]
public sealed class AuthSessionAdmissionReaderTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 8, 10, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Reader_requires_the_exact_active_member_and_unexpired_active_session()
    {
        string databaseName = $"auth-session-admission-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid activeMemberId = Guid.NewGuid();
        Guid activeSessionId = Guid.NewGuid();
        Guid signedOutMemberId = Guid.NewGuid();
        Guid signedOutSessionId = Guid.NewGuid();
        Guid disabledMemberId = Guid.NewGuid();
        Guid disabledSessionId = Guid.NewGuid();
        Guid expiredMemberId = Guid.NewGuid();
        Guid expiredSessionId = Guid.NewGuid();

        await using (AuthDbContext tenant = CreateDbContext(databaseName, databaseRoot, "tenant-a"))
        {
            Member active = CreateMember(activeMemberId, "active@example.com");
            Assert.True(active.StartSession(
                new MemberSessionId(activeSessionId),
                "active-refresh-hash",
                Now.AddHours(1),
                Now).IsSuccess);

            Member signedOut = CreateMember(signedOutMemberId, "signed-out@example.com");
            Assert.True(signedOut.StartSession(
                new MemberSessionId(signedOutSessionId),
                "signed-out-refresh-hash",
                Now.AddHours(1),
                Now).IsSuccess);
            Assert.True(signedOut.SignOutSession(new MemberSessionId(signedOutSessionId), Now).IsSuccess);

            Member disabled = CreateMember(disabledMemberId, "disabled@example.com");
            Assert.True(disabled.StartSession(
                new MemberSessionId(disabledSessionId),
                "disabled-refresh-hash",
                Now.AddHours(1),
                Now).IsSuccess);
            Assert.True(disabled.Disable("disabled for test", Guid.NewGuid(), Now).IsSuccess);

            Member expired = CreateMember(expiredMemberId, "expired@example.com", Now.AddHours(-2));
            Assert.True(expired.StartSession(
                new MemberSessionId(expiredSessionId),
                "expired-refresh-hash",
                Now.AddHours(-1),
                Now.AddHours(-2)).IsSuccess);

            tenant.Members.AddRange(active, signedOut, disabled, expired);
            await tenant.SaveChangesAsync();
        }

        await using AuthDbContext worker = CreateDbContext(databaseName, databaseRoot, "worker-default");
        var reader = new AuthSessionAdmissionReader(worker, new FixedClock(Now));

        Assert.True(await reader.IsActiveAsync("tenant-a", activeMemberId, activeSessionId));
        Assert.False(await reader.IsActiveAsync("tenant-a", signedOutMemberId, signedOutSessionId));
        Assert.False(await reader.IsActiveAsync("tenant-a", disabledMemberId, disabledSessionId));
        Assert.False(await reader.IsActiveAsync("tenant-a", expiredMemberId, expiredSessionId));
        Assert.False(await reader.IsActiveAsync("tenant-a", Guid.NewGuid(), activeSessionId));
        Assert.False(await reader.IsActiveAsync("tenant-a", activeMemberId, Guid.NewGuid()));
        Assert.False(await reader.IsActiveAsync("tenant-b", activeMemberId, activeSessionId));
        Assert.False(await reader.IsActiveAsync("tenant-a", Guid.Empty, activeSessionId));
        Assert.False(await reader.IsActiveAsync("tenant-a", activeMemberId, Guid.Empty));
    }

    [Fact]
    public async Task Disabling_browser_runtime_rejects_retained_bound_sessions_but_preserves_ordinary_sessions()
    {
        await using AuthDbContext db = CreateDbContext(Guid.NewGuid().ToString(), new InMemoryDatabaseRoot(), "tenant-a");
        Member member = CreateMember(Guid.NewGuid(), "browser-admission@example.test");
        var ordinary = member.StartSession(new(Guid.NewGuid()), "ordinary-hash", Now.AddHours(1), Now).Value;
        var bound = member.StartSession(new(Guid.NewGuid()), "bound-hash", Now.AddHours(1), Now).Value;
        bound.BindRememberedBrowser(Guid.NewGuid(), Guid.NewGuid(), 1, member.SecurityEpoch);
        db.Members.Add(member);
        await db.SaveChangesAsync();
        var options = Options.Create(new RememberedBrowserOptions { Enabled = false });
        var sessionReader = new AuthSessionAdmissionReader(db, new FixedClock(Now), options);
        var browserReader = new AuthRememberedSessionAdmissionReader(db, options, new FixedClock(Now));

        Assert.True(await sessionReader.IsActiveAsync("tenant-a", member.Id.Value, ordinary.Id.Value));
        Assert.False(await sessionReader.IsActiveAsync("tenant-a", member.Id.Value, bound.Id.Value));
        Assert.True(await browserReader.IsAdmittedAsync("tenant-a", member.Id.Value, ordinary.Id.Value, null));
        Assert.False(await browserReader.IsAdmittedAsync("tenant-a", member.Id.Value, bound.Id.Value, null));
        Assert.False(await browserReader.IsAdmittedAsync("tenant-a", member.Id.Value, bound.Id.Value, new string('a', 64)));
    }

    private static Member CreateMember(
        Guid memberId,
        string email,
        DateTimeOffset? registeredAtUtc = null) =>
        Member.Create(
            new MemberId(memberId),
            "tenant-a",
            email,
            DomainMemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            registeredAtUtc ?? Now).Value;

    private static AuthDbContext CreateDbContext(
        string databaseName,
        InMemoryDatabaseRoot databaseRoot,
        string scopeId) =>
        new(
            new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName, databaseRoot)
                .Options,
            new TestScopeContext(scopeId));

    private sealed class FixedClock(DateTimeOffset nowUtc) : ISystemClock
    {
        public DateTimeOffset UtcNow => nowUtc;
    }

    private sealed class TestScopeContext(string scopeId) : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => scopeId;
        public bool TryRestoreScope(string? candidate) =>
            string.Equals(scopeId, candidate, StringComparison.Ordinal);
    }
}
