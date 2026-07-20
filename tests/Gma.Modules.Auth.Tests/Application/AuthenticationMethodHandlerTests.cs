namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Handlers;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
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
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await handler.HandleAsync(
            new SetMemberPasswordCommand(
                member.Id.Value,
                session.Id.Value,
                "SafePassword123!",
                null,
                "refresh-hash"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Succeeded);
        Assert.True(member.HasPassword);
        Assert.Equal("new-refresh-hash", session.RefreshTokenHash);
        MemberAuthenticationMethodChangedDomainEvent changed = Assert.Single(
            member.DomainEvents.OfType<MemberAuthenticationMethodChangedDomainEvent>());
        Assert.Equal(MemberAuthenticationMethodChange.Added, changed.Change);
    }

    [Fact]
    public async Task Password_update_rotates_current_session_and_revokes_every_sibling_session()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreatePasswordMember();
        MemberSession current = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "current-refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberSession sibling = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "sibling-refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new SetMemberPasswordCommandHandler(
            repository,
            new FakePasswordHashingService(),
            new AllowAllPasswordBlocklist(),
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await handler.HandleAsync(
            new SetMemberPasswordCommand(
                member.Id.Value,
                current.Id.Value,
                "NewSafePassword123!",
                "CurrentPassword123!",
                "current-refresh-hash"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Succeeded);
        Assert.Equal("hash:NewSafePassword123!", member.PasswordHash);
        Assert.True(current.IsActive);
        Assert.Equal("new-refresh-hash", current.RefreshTokenHash);
        Assert.False(sibling.IsActive);
        Assert.Equal(1, Assert.Single(
            member.DomainEvents.OfType<MemberSessionsRevokedDomainEvent>()).RevokedSessionCount);
    }

    [Fact]
    public async Task Password_creation_rechecks_session_freshness_after_blocklist_work()
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
        var clock = new MutableClock(Now);
        var handler = new SetMemberPasswordCommandHandler(
            repository,
            new FakePasswordHashingService(),
            new AdvancingPasswordBlocklist(clock, Now.AddMinutes(11)),
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            clock,
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions { ExternalLinkSessionFreshnessMinutes = 10 }));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await handler.HandleAsync(
            new SetMemberPasswordCommand(
                member.Id.Value,
                session.Id.Value,
                "SafePassword123!",
                null,
                "refresh-hash"),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.FreshAuthenticationRequired, result.Error);
        Assert.False(member.HasPassword);
        Assert.Equal("refresh-hash", session.RefreshTokenHash);
    }

    [Fact]
    public async Task Password_update_replay_revokes_sessions_without_changing_the_password()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreatePasswordMember();
        MemberSession current = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "old-refresh-hash",
            Now.AddDays(1),
            Now).Value;
        _ = member.RefreshSession(
            current.Id,
            "old-refresh-hash",
            "current-refresh-hash",
            Now.AddDays(1),
            Now);
        MemberSession sibling = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "sibling-refresh-hash",
            Now.AddDays(1),
            Now).Value;
        member.ClearDomainEvents();
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new SetMemberPasswordCommandHandler(
            repository,
            new FakePasswordHashingService(),
            new AllowAllPasswordBlocklist(),
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await handler.HandleAsync(
            new SetMemberPasswordCommand(
                member.Id.Value,
                current.Id.Value,
                "NewSafePassword123!",
                "CurrentPassword123!",
                "old-refresh-hash"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.RefreshTokenReuseDetected);
        Assert.Equal("hash:CurrentPassword123!", member.PasswordHash);
        Assert.False(current.IsActive);
        Assert.False(sibling.IsActive);
        Assert.Empty(member.DomainEvents.OfType<MemberAuthenticationMethodChangedDomainEvent>());
        Assert.Equal(2, Assert.Single(
            member.DomainEvents.OfType<MemberSessionsRevokedDomainEvent>()).RevokedSessionCount);
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
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await handler.HandleAsync(
            new RemoveMemberPasswordCommand(
                member.Id.Value,
                session.Id.Value,
                "CurrentPassword123!",
                "refresh-hash"),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.AuthenticationMethodRequired, result.Error);
        Assert.True(member.HasPassword);
    }

    [Fact]
    public async Task Password_removal_rotates_current_and_revokes_only_password_siblings()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreatePasswordMember();
        _ = member.LinkExternalIdentity(
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            "google-subject",
            Now);
        MemberSession current = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "current-refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberSession passwordSibling = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "password-sibling-refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberSession externalSibling = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "external-sibling-refresh-hash",
            Now.AddDays(1),
            Now,
            MemberAuthenticationMethods.External("google")).Value;
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new RemoveMemberPasswordCommandHandler(
            repository,
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await handler.HandleAsync(
            new RemoveMemberPasswordCommand(
                member.Id.Value,
                current.Id.Value,
                "CurrentPassword123!",
                "current-refresh-hash"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Succeeded);
        Assert.False(member.HasPassword);
        Assert.True(current.IsActive);
        Assert.Equal("new-refresh-hash", current.RefreshTokenHash);
        Assert.False(passwordSibling.IsActive);
        Assert.True(externalSibling.IsActive);
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
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> denied = await handler.HandleAsync(
            new UnlinkExternalIdentityCommand(
                member.Id.Value,
                googleSession.Id.Value,
                google.Id.Value,
                null,
                "google-refresh-hash"),
            CancellationToken.None);
        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> unlinked = await handler.HandleAsync(
            new UnlinkExternalIdentityCommand(
                member.Id.Value,
                microsoftSession.Id.Value,
                google.Id.Value,
                null,
                "microsoft-refresh-hash"),
            CancellationToken.None);

        Assert.True(denied.IsFailure);
        Assert.Equal(AuthApplicationErrors.AlternateAuthenticationRequired, denied.Error);
        Assert.True(unlinked.IsSuccess);
        Assert.True(unlinked.Value.Succeeded);
        Assert.False(googleSession.IsActive);
        Assert.True(microsoftSession.IsActive);
        Assert.Equal("new-refresh-hash", microsoftSession.RefreshTokenHash);
        Assert.Equal(microsoft.Id, Assert.Single(member.ExternalIdentities).Id);
    }

    [Fact]
    public async Task Unlinking_current_provider_rotates_current_and_revokes_provider_siblings()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreatePasswordMember();
        MemberExternalIdentity google = member.LinkExternalIdentity(
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            "google-subject",
            Now).Value;
        string googleMethod = MemberAuthenticationMethods.External("google");
        MemberSession current = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "current-refresh-hash",
            Now.AddDays(1),
            Now,
            googleMethod).Value;
        MemberSession providerSibling = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "provider-sibling-refresh-hash",
            Now.AddDays(1),
            Now,
            googleMethod).Value;
        MemberSession passwordSibling = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "password-sibling-refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberRepository repository = await PersistAsync(dbContext, member);
        var handler = new UnlinkExternalIdentityCommandHandler(
            repository,
            CreatePasswordProofService(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            new FakeClock(),
            new RandomIdGenerator(),
            Options.Create(new AuthApplicationOptions()));

        Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await handler.HandleAsync(
            new UnlinkExternalIdentityCommand(
                member.Id.Value,
                current.Id.Value,
                google.Id.Value,
                "CurrentPassword123!",
                "current-refresh-hash"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Succeeded);
        Assert.Empty(member.ExternalIdentities);
        Assert.True(current.IsActive);
        Assert.Equal("new-refresh-hash", current.RefreshTokenHash);
        Assert.Contains(AuthenticationMethodReferences.Password, current.AuthenticationMethodReferences);
        Assert.False(providerSibling.IsActive);
        Assert.True(passwordSibling.IsActive);
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

    private static PasswordProofService CreatePasswordProofService() =>
        new(
            new FakePasswordHashingService(),
            new AllowAllAttemptLimiter(),
            Options.Create(new AuthApplicationOptions()));

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

    private sealed class AdvancingPasswordBlocklist(MutableClock clock, DateTimeOffset nextUtc)
        : IPasswordBlocklist
    {
        public ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken)
        {
            clock.UtcNow = nextUtc;
            return ValueTask.FromResult(false);
        }
    }

    private sealed class AllowAllAttemptLimiter : IAuthenticationAttemptLimiter
    {
        public ValueTask<AuthenticationAttemptLease?> TryAcquireAsync(
            string scopeId,
            string purpose,
            string target,
            DateTimeOffset nowUtc,
            AuthenticationAttemptPolicy policy,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<AuthenticationAttemptLease?>(
                new AuthenticationAttemptLease(Guid.NewGuid(), nowUtc));

        public ValueTask RecordSuccessAsync(
            string scopeId,
            string purpose,
            string target,
            AuthenticationAttemptLease lease,
            CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private sealed class FakeTokenService : ITokenService
    {
        public string GenerateAccessToken(AccessTokenClaims claims) => "access-token";
        public string GenerateRefreshToken() => "new-refresh";
        public MemberId? GetMemberId(string accessToken, bool validateLifetime) => null;
        public AccessTokenClaims? GetAccessTokenClaims(string accessToken, bool validateLifetime) => null;
    }

    private sealed class FakeRefreshTokenHashingService : IRefreshTokenHashingService
    {
        public string HashRefreshToken(string refreshToken) => $"{refreshToken}-hash";
        public IReadOnlyList<string> GetCandidateHashes(string refreshToken) => [refreshToken];
    }

    private sealed class FakeClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
    }

    private sealed class MutableClock(DateTimeOffset nowUtc) : ISystemClock
    {
        public DateTimeOffset UtcNow { get; set; } = nowUtc;
    }

    private sealed class RandomIdGenerator : IIdGenerator
    {
        public Guid NewId() => Guid.NewGuid();
    }

    private sealed class TestScopeContext : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => "tenant-a";
        public bool TryRestoreScope(string? scopeId) =>
            string.Equals(this.ScopeId, scopeId, StringComparison.Ordinal);
    }
}
