namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Framework.Results;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Handlers;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthenticationMethodHandlerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Fresh_external_session_can_add_a_password_without_a_previous_password()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateExternalMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "refresh-hash",
            Now.AddDays(1),
            Now,
            MemberAuthenticationMethods.External("google")).Value;
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new SetMemberPasswordCommandHandler(
            repository,
            new FakePasswordHashingService(),
            new AllowAllPasswordBlocklist(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result result = await handler.HandleAsync(
            new SetMemberPasswordCommand(member.Id.Value, session.Id.Value, "SafePassword123!", null),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(member.HasPassword);
        MemberAuthenticationMethodChangedDomainEvent changed = Assert.Single(
            member.DomainEvents.OfType<MemberAuthenticationMethodChangedDomainEvent>());
        Assert.Equal(MemberAuthenticationMethodChange.Added, changed.Change);
    }

    [Fact]
    public async Task Password_removal_cannot_lock_a_password_only_member_out()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreatePasswordMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new RemoveMemberPasswordCommandHandler(
            repository,
            new FakePasswordHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result result = await handler.HandleAsync(
            new RemoveMemberPasswordCommand(member.Id.Value, session.Id.Value, "CurrentPassword123!"),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.AuthenticationMethodRequired, result.Error);
        Assert.True(member.HasPassword);
    }

    [Fact]
    public async Task Provider_used_by_the_current_session_requires_alternate_authentication_before_unlink()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateExternalMember();
        MemberExternalIdentity google = Assert.Single(member.ExternalIdentities);
        MemberExternalIdentity microsoft = member.LinkExternalIdentity(
            new MemberExternalIdentityId(Guid.NewGuid()),
            "microsoft",
            "https://login.microsoftonline.com/tenant/v2.0",
            "microsoft-subject",
            Now).Value;
        MemberSession googleSession = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "google-refresh-hash",
            Now.AddDays(1),
            Now,
            MemberAuthenticationMethods.External("google")).Value;
        MemberSession microsoftSession = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "microsoft-refresh-hash",
            Now.AddDays(1),
            Now,
            MemberAuthenticationMethods.External("microsoft")).Value;
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new UnlinkExternalIdentityCommandHandler(
            repository,
            new FakePasswordHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result denied = await handler.HandleAsync(
            new UnlinkExternalIdentityCommand(member.Id.Value, googleSession.Id.Value, google.Id.Value, null),
            CancellationToken.None);
        Result unlinked = await handler.HandleAsync(
            new UnlinkExternalIdentityCommand(member.Id.Value, microsoftSession.Id.Value, google.Id.Value, null),
            CancellationToken.None);

        Assert.True(denied.IsFailure);
        Assert.Equal(AuthApplicationErrors.AlternateAuthenticationRequired, denied.Error);
        Assert.True(unlinked.IsSuccess);
        Assert.Equal(microsoft.Id, Assert.Single(member.ExternalIdentities).Id);
    }

    [Fact]
    public async Task Administrative_password_reset_revokes_sessions_and_raises_a_security_event()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreatePasswordMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new ResetMemberPasswordCommandHandler(
            repository,
            new FakePasswordHashingService(),
            new AllowAllPasswordBlocklist(),
            new FakeClock(),
            new RandomIdGenerator());

        Result result = await handler.HandleAsync(
            new ResetMemberPasswordCommand(member.Id.Value, "NewSafePassword123!"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.False(session.IsActive);
        Assert.Contains(member.DomainEvents, domainEvent => domainEvent is MemberSessionsRevokedDomainEvent);
        MemberAuthenticationMethodChangedDomainEvent changed = Assert.Single(
            member.DomainEvents.OfType<MemberAuthenticationMethodChangedDomainEvent>());
        Assert.Equal(MemberAuthenticationMethodChange.Updated, changed.Change);
    }

    private static AuthDbContext CreateDbContext() => new(
        new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-method-handlers-{Guid.NewGuid():N}")
            .Options,
        new TestScopeContext());

    private static async Task<MemberRepository> PersistAsync(AuthDbContext dbContext, Member member)
    {
        MemberRepository repository = new(dbContext);
        await repository.AddAsync(member, CancellationToken.None);
        await dbContext.SaveChangesAsync();
        return repository;
    }

    private static Member CreatePasswordMember() => Member.Create(
        new MemberId(Guid.NewGuid()),
        "tenant-a",
        "member@example.com",
        MemberUsernameType.Email,
        "hash:CurrentPassword123!",
        new MemberUsernameId(Guid.NewGuid()),
        Guid.NewGuid(),
        Now).Value;

    private static Member CreateExternalMember() => Member.CreateExternal(
        new MemberId(Guid.NewGuid()),
        "tenant-a",
        "member@example.com",
        new MemberUsernameId(Guid.NewGuid()),
        new MemberExternalIdentityId(Guid.NewGuid()),
        "google",
        "https://accounts.google.com",
        "google-subject",
        Guid.NewGuid(),
        Now).Value;

    private sealed class FakePasswordHashingService : IPasswordHashingService
    {
        public string HashPassword(string password) => $"hash:{password}";

        public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password) =>
            string.Equals(passwordHash, this.HashPassword(password), StringComparison.Ordinal)
                ? PasswordVerificationOutcome.Success
                : PasswordVerificationOutcome.Unknown;
    }

    private sealed class AllowAllPasswordBlocklist : IPasswordBlocklist
    {
        public ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken) =>
            ValueTask.FromResult(false);
    }

    private sealed class FakeClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
    }

    private sealed class RandomIdGenerator : IIdGenerator
    {
        public Guid NewId() => Guid.NewGuid();
    }

    private sealed class TestScopeContext : Gma.Framework.Scoping.IScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => "tenant-a";
    }
}
