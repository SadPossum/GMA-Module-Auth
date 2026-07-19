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
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class MultiFactorAuthenticationFlowTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Password_login_creates_no_session_until_the_challenge_is_completed()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        member.ClearDomainEvents();
        MultiFactorAuthenticationService multiFactor = CreateMultiFactorService(dbContext);
        LoginMemberCommandHandler loginHandler = new(
            new MemberRepository(dbContext),
            new FakePasswordHashingService(),
            new PasswordProofService(new FakePasswordHashingService(), new AllowAllAttemptLimiter()),
            multiFactor,
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            Options.Create(new AuthApplicationOptions()),
            new TestScopeContext(),
            new FakeClock(),
            new RandomIdGenerator());

        Result<PrimaryAuthenticationResult> login = await loginHandler.HandleAsync(
            new LoginMemberCommand("member@example.com", "password", "203.0.113.20", "test-agent"),
            CancellationToken.None);

        Assert.True(login.IsSuccess);
        Assert.True(login.Value.RequiresMultiFactor);
        Assert.Null(login.Value.Tokens);
        Assert.Empty(member.Sessions);
        MemberAuthenticationChallenge challenge = Assert.Single(dbContext.MemberAuthenticationChallenges.Local);
        Assert.Equal("203.0.113.20", challenge.IpAddress);
        await dbContext.SaveChangesAsync();

        CompleteMultiFactorChallengeCommandHandler completionHandler = new(
            new MemberAuthenticationChallengeRepository(dbContext),
            new MemberTotpAuthenticatorRepository(dbContext),
            new MemberRepository(dbContext),
            multiFactor,
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            Options.Create(new AuthApplicationOptions()),
            new FakeClock(),
            new RandomIdGenerator());
        Result<MultiFactorChallengeCompletion> invalid = await completionHandler.HandleAsync(
            new CompleteMultiFactorChallengeCommand(
                login.Value.MultiFactorChallenge!.ChallengeToken,
                MultiFactorCodeType.Totp,
                "wrong"),
            CancellationToken.None);

        Assert.True(invalid.IsSuccess);
        Assert.False(invalid.Value.Succeeded);
        Assert.Equal(1, challenge.FailedAttemptCount);
        Assert.Empty(member.Sessions);
        await dbContext.SaveChangesAsync();

        Result<MultiFactorChallengeCompletion> completed = await completionHandler.HandleAsync(
            new CompleteMultiFactorChallengeCommand(
                login.Value.MultiFactorChallenge.ChallengeToken,
                MultiFactorCodeType.Totp,
                FakeTotpProvider.ValidCode),
            CancellationToken.None);

        Assert.True(completed.IsSuccess);
        Assert.True(completed.Value.Succeeded);
        Assert.NotNull(completed.Value.Tokens);
        MemberSession session = Assert.Single(member.Sessions);
        Assert.Equal(AuthenticationContextReferences.MultiFactor, session.AuthenticationContextReference);
        Assert.Equal(
            [AuthenticationMethodReferences.Password, AuthenticationMethodReferences.OneTimePassword, AuthenticationMethodReferences.MultiFactor],
            session.AuthenticationMethodReferences);
        Assert.NotNull(challenge.ConsumedAtUtc);
        Assert.Equal(42, authenticator.LastAcceptedTimeStep);
    }

    [Fact]
    public async Task Activation_rotates_the_session_and_returns_recovery_codes_once()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now,
            authenticationEvidence: SessionAuthenticationEvidence.Password(Now)).Value;
        MemberTotpAuthenticator authenticator = CreatePendingAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        ActivateTotpCommandHandler handler = new(
            new MemberRepository(dbContext),
            new MemberTotpAuthenticatorRepository(dbContext),
            CreateMultiFactorService(dbContext),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            Options.Create(new AuthApplicationOptions()),
            new TestScopeContext(),
            new FakeClock(),
            new RandomIdGenerator());

        Result<TotpActivationResponse> result = await handler.HandleAsync(
            new ActivateTotpCommand(
                member.Id.Value,
                session.Id.Value,
                FakeTotpProvider.ValidCode,
                "old-refresh"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(authenticator.IsActive);
        Assert.Equal(10, authenticator.UnusedRecoveryCodeCount);
        Assert.Equal(10, result.Value.RecoveryCodes.Count);
        Assert.Equal("new-refresh", result.Value.RefreshToken);
        Assert.Equal("hash:new-refresh", session.RefreshTokenHash);
        Assert.Equal(AuthenticationContextReferences.MultiFactor, session.AuthenticationContextReference);
        Assert.Contains(member.DomainEvents, item => item is MemberAuthenticationMethodChangedDomainEvent);
    }

    [Fact]
    public async Task Invalid_management_factor_is_recorded_durably_without_disabling_totp()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        MemberMultiFactorFailureAttemptRepository failureRepository = new(dbContext);
        DisableTotpCommandHandler handler = new(
            new MemberRepository(dbContext),
            new MemberTotpAuthenticatorRepository(dbContext),
            new MemberAuthenticationChallengeRepository(dbContext),
            failureRepository,
            CreateMultiFactorService(dbContext),
            new AllowAllAttemptLimiter(),
            new FakeTokenService(),
            new FakeRefreshTokenHashingService(),
            Options.Create(new AuthApplicationOptions()),
            new TestScopeContext(),
            new FakeClock(),
            new RandomIdGenerator());

        Result<MultiFactorDisableCompletion> result = await handler.HandleAsync(
            new DisableTotpCommand(
                member.Id.Value,
                session.Id.Value,
                MultiFactorCodeType.Totp,
                "wrong",
                "old-refresh"),
            CancellationToken.None);
        await dbContext.SaveChangesAsync();

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.Succeeded);
        Assert.True(authenticator.IsActive);
        Assert.True(session.IsActive);
        Assert.Equal(1, await failureRepository.CountSinceAsync(
            member.Id,
            MemberMultiFactorFailureAttempt.ManagementPurpose,
            Now.AddMinutes(-15),
            CancellationToken.None));
    }

    [Fact]
    public async Task Administrative_reset_revokes_factor_challenges_and_sessions()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        MemberAuthenticationChallenge challenge = MemberAuthenticationChallenge.Create(
            new MemberAuthenticationChallengeId(Guid.NewGuid()),
            member.Id,
            member.ScopeId,
            "hash:challenge-token",
            MemberAuthenticationMethods.Password,
            SessionAuthenticationEvidence.Password(Now),
            null,
            null,
            5,
            Now.AddMinutes(5),
            Now).Value;
        dbContext.AddRange(member, authenticator, challenge);
        await dbContext.SaveChangesAsync();
        member.ClearDomainEvents();
        authenticator.ClearDomainEvents();
        ResetMemberMultiFactorAuthenticationCommandHandler handler = new(
            new MemberRepository(dbContext),
            new MemberTotpAuthenticatorRepository(dbContext),
            new MemberAuthenticationChallengeRepository(dbContext),
            new FakeClock(),
            new RandomIdGenerator());

        Result result = await handler.HandleAsync(
            new ResetMemberMultiFactorAuthenticationCommand(
                member.Id.Value,
                "support-admin",
                "verified account recovery"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.False(authenticator.IsActive);
        Assert.False(session.IsActive);
        Assert.NotNull(challenge.RevokedAtUtc);
        Assert.Contains(authenticator.DomainEvents, item => item is MemberMultiFactorAuthenticationResetDomainEvent);
        Assert.Contains(member.DomainEvents, item => item is MemberAuthenticationMethodChangedDomainEvent);
        Assert.Contains(member.DomainEvents, item => item is MemberSessionsRevokedDomainEvent);
    }

    private static AuthDbContext CreateDbContext() => new(
        new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-mfa-{Guid.NewGuid():N}")
            .Options,
        new TestScopeContext());

    private static Member CreateMember() => Member.Create(
        new MemberId(Guid.NewGuid()),
        "tenant-a",
        "member@example.com",
        MemberUsernameType.Email,
        "hash:password",
        new MemberUsernameId(Guid.NewGuid()),
        Guid.NewGuid(),
        Now).Value;

    private static MemberTotpAuthenticator CreatePendingAuthenticator(Member member) =>
        MemberTotpAuthenticator.BeginEnrollment(
            new MemberTotpAuthenticatorId(Guid.NewGuid()),
            member.Id,
            member.ScopeId,
            "protected-secret",
            Now.AddMinutes(10),
            Now).Value;

    private static MemberTotpAuthenticator CreateActiveAuthenticator(Member member)
    {
        MemberTotpAuthenticator authenticator = CreatePendingAuthenticator(member);
        Assert.True(authenticator.Activate(41, CreateRecoveryCodes(), Now).IsSuccess);
        authenticator.ClearDomainEvents();
        return authenticator;
    }

    private static TotpRecoveryCodeRegistration[] CreateRecoveryCodes() =>
        Enumerable.Range(0, 10)
            .Select(index => new TotpRecoveryCodeRegistration(
                new MemberTotpRecoveryCodeId(Guid.NewGuid()),
                $"hash:RECOVERY{index}"))
            .ToArray();

    private static MultiFactorAuthenticationService CreateMultiFactorService(AuthDbContext dbContext) => new(
        new MemberTotpAuthenticatorRepository(dbContext),
        new MemberAuthenticationChallengeRepository(dbContext),
        new FakeTotpProvider(),
        new FakeSecretProtector(),
        new FakeMultiFactorTokenService(),
        Options.Create(new AuthApplicationOptions()),
        new FakeClock(),
        new RandomIdGenerator());

    private sealed class FakeTotpProvider : ITimeBasedOneTimePasswordProvider
    {
        public const string ValidCode = "123456";
        public bool IsAvailable => true;
        public GeneratedTotpSecret GenerateSecret() => new([1, 2, 3, 4], "AEBAGBA");
        public string CreateProvisioningUri(string accountName, string encodedSecret) =>
            $"otpauth://totp/GMA:{accountName}?secret={encodedSecret}";
        public TotpVerificationResult Verify(byte[] secret, string code, DateTimeOffset nowUtc) =>
            string.Equals(code, ValidCode, StringComparison.Ordinal)
                ? new TotpVerificationResult(true, 42)
                : TotpVerificationResult.Invalid;
    }

    private sealed class FakeSecretProtector : IAuthenticatorSecretProtector
    {
        public bool IsAvailable => true;
        public string Protect(byte[] secret) => "protected-secret";
        public byte[] Unprotect(string protectedSecret) => [1, 2, 3, 4];
    }

    private sealed class FakeMultiFactorTokenService : IMultiFactorTokenService
    {
        public MultiFactorTokenMaterial GenerateChallengeToken() =>
            new("challenge-token", "hash:challenge-token");

        public IReadOnlyList<string> GetCandidateChallengeTokenHashes(string token) => [$"hash:{token}"];

        public IReadOnlyList<RecoveryCodeMaterial> GenerateRecoveryCodes(int count) =>
            Enumerable.Range(0, count)
                .Select(index => new RecoveryCodeMaterial($"RECOVERY-{index}", $"hash:RECOVERY{index}"))
                .ToArray();

        public IReadOnlyList<string> GetCandidateRecoveryCodeHashes(string code) =>
            [$"hash:{code.Replace("-", string.Empty, StringComparison.Ordinal).ToUpperInvariant()}"];
    }

    private sealed class FakePasswordHashingService : IPasswordHashingService
    {
        public string HashPassword(string password) => $"hash:{password}";
        public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password) =>
            string.Equals(passwordHash, this.HashPassword(password), StringComparison.Ordinal)
                ? PasswordVerificationOutcome.Success
                : PasswordVerificationOutcome.Unknown;
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
        public string HashRefreshToken(string refreshToken) => $"hash:{refreshToken}";
        public IReadOnlyList<string> GetCandidateHashes(string refreshToken) => [$"hash:{refreshToken}"];
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
