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
public sealed class PasswordStepUpTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Password_step_up_rotates_refresh_token_and_records_new_evidence()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now.AddHours(-2),
            MemberAuthenticationMethods.External("google"),
            SessionAuthenticationEvidence.External(Now.AddHours(-2))).Value;
        dbContext.Members.Add(member);
        await dbContext.SaveChangesAsync();
        RecordingTokenService tokenService = new();
        StepUpWithPasswordCommandHandler handler = CreateHandler(dbContext, tokenService);

        Result<AuthTokensResponse> result = await handler.HandleAsync(
            new StepUpWithPasswordCommand(
                member.Id.Value,
                session.Id.Value,
                "CurrentPassword123!",
                "old-refresh"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("new-refresh", result.Value.RefreshToken);
        Assert.Equal("hash:new-refresh", session.RefreshTokenHash);
        Assert.Equal("hash:old-refresh", session.PreviousRefreshTokenHash);
        Assert.Equal(AuthenticationContextReferences.Password, session.AuthenticationContextReference);
        Assert.Equal([AuthenticationMethodReferences.Password], session.AuthenticationMethodReferences);
        Assert.Equal(Now, session.AuthenticatedAtUtc);
        Assert.Equal(Now, tokenService.Claims!.AuthenticationEvidence.AuthenticatedAtUtc);
        Assert.IsType<MemberSessionReauthenticatedDomainEvent>(
            Assert.Single(member.DomainEvents.OfType<MemberSessionReauthenticatedDomainEvent>()));
        Assert.Empty(member.DomainEvents.OfType<MemberAuthenticatedDomainEvent>());
    }

    [Fact]
    public async Task Invalid_password_does_not_rotate_or_upgrade_the_session()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now.AddHours(-2),
            MemberAuthenticationMethods.External("google")).Value;
        dbContext.Members.Add(member);
        await dbContext.SaveChangesAsync();

        Result<AuthTokensResponse> result = await CreateHandler(dbContext, new RecordingTokenService()).HandleAsync(
            new StepUpWithPasswordCommand(member.Id.Value, session.Id.Value, "wrong", "old-refresh"),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.CredentialsNotValid, result.Error);
        Assert.Equal("hash:old-refresh", session.RefreshTokenHash);
        Assert.Equal(AuthenticationContextReferences.External, session.AuthenticationContextReference);
        Assert.Empty(member.DomainEvents.OfType<MemberSessionReauthenticatedDomainEvent>());
    }

    [Fact]
    public async Task Reusing_the_pre_step_up_refresh_token_revokes_all_sessions()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now).Value;
        MemberSession otherSession = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:other-refresh",
            Now.AddDays(1),
            Now).Value;
        dbContext.Members.Add(member);
        await dbContext.SaveChangesAsync();
        StepUpWithPasswordCommandHandler handler = CreateHandler(dbContext, new RecordingTokenService());
        StepUpWithPasswordCommand command = new(
            member.Id.Value,
            session.Id.Value,
            "CurrentPassword123!",
            "old-refresh");

        Assert.True((await handler.HandleAsync(command, CancellationToken.None)).IsSuccess);
        Result<AuthTokensResponse> replay = await handler.HandleAsync(command, CancellationToken.None);

        Assert.True(replay.IsFailure);
        Assert.Equal(AuthDomainErrors.RefreshTokenReused, replay.Error);
        Assert.False(session.IsActive);
        Assert.False(otherSession.IsActive);
    }

    [Fact]
    public void Ordinary_refresh_preserves_authentication_evidence()
    {
        Member member = CreateMember();
        SessionAuthenticationEvidence evidence = SessionAuthenticationEvidence.Password(Now.AddHours(-1));
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now.AddHours(-3),
            authenticationEvidence: evidence).Value;

        Result<MemberSession> refreshed = member.RefreshSession(
            session.Id,
            "hash:old-refresh",
            "hash:new-refresh",
            Now.AddDays(2),
            Now);

        Assert.True(refreshed.IsSuccess);
        Assert.Equal(evidence.ContextReference, session.AuthenticationContextReference);
        Assert.Equal(evidence.MethodReferences, session.AuthenticationMethodReferences);
        Assert.Equal(evidence.AuthenticatedAtUtc, session.AuthenticatedAtUtc);
    }

    private static StepUpWithPasswordCommandHandler CreateHandler(
        AuthDbContext dbContext,
        RecordingTokenService tokenService) =>
        new(
            new MemberRepository(dbContext),
            new FakePasswordHashingService(),
            new PasswordProofService(new FakePasswordHashingService(), new AllowAllAttemptLimiter()),
            tokenService,
            new FakeRefreshTokenHashingService(),
            Options.Create(new AuthApplicationOptions()),
            new TestScopeContext(),
            new FakeClock(),
            new RandomIdGenerator());

    private static AuthDbContext CreateDbContext() => new(
        new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-step-up-{Guid.NewGuid():N}")
            .Options,
        new TestScopeContext());

    private static Member CreateMember() => Member.Create(
        new MemberId(Guid.NewGuid()),
        "tenant-a",
        "member@example.com",
        MemberUsernameType.Email,
        "hash:CurrentPassword123!",
        new MemberUsernameId(Guid.NewGuid()),
        Guid.NewGuid(),
        Now.AddDays(-1)).Value;

    private sealed class FakePasswordHashingService : IPasswordHashingService
    {
        public string HashPassword(string password) => $"hash:{password}";

        public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password) =>
            string.Equals(passwordHash, this.HashPassword(password), StringComparison.Ordinal)
                ? PasswordVerificationOutcome.Success
                : PasswordVerificationOutcome.Unknown;
    }

    private sealed class AllowAllAttemptLimiter : IAuthenticationAttemptLimiter
    {
        public ValueTask<bool> IsAllowedAsync(
            string scopeId,
            string purpose,
            string target,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken) => ValueTask.FromResult(true);

        public ValueTask RecordFailureAsync(
            string scopeId,
            string purpose,
            string target,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken) => ValueTask.CompletedTask;

        public ValueTask RecordSuccessAsync(
            string scopeId,
            string purpose,
            string target,
            CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private sealed class FakeRefreshTokenHashingService : IRefreshTokenHashingService
    {
        public string HashRefreshToken(string refreshToken) => $"hash:{refreshToken}";
        public IReadOnlyList<string> GetCandidateHashes(string refreshToken) => [$"hash:{refreshToken}"];
    }

    private sealed class RecordingTokenService : ITokenService
    {
        public AccessTokenClaims? Claims { get; private set; }

        public string GenerateAccessToken(AccessTokenClaims claims)
        {
            this.Claims = claims;
            return "access-token";
        }

        public string GenerateRefreshToken() => "new-refresh";
        public MemberId? GetMemberId(string accessToken, bool validateLifetime) => null;
        public AccessTokenClaims? GetAccessTokenClaims(string accessToken, bool validateLifetime) => null;
    }

    private sealed class FakeClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
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
