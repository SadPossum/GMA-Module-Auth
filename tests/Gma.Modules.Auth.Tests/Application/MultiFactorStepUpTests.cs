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
public sealed class MultiFactorStepUpTests
{
    private const string Password = "CurrentPassword123!";
    private static readonly DateTimeOffset Now = new(2026, 8, 22, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Password_and_totp_step_up_rotate_the_existing_session_with_fresh_mfa_evidence()
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
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        MemberMultiFactorFailureAttempt priorFailure = MemberMultiFactorFailureAttempt.Create(
            new MemberMultiFactorFailureAttemptId(Guid.NewGuid()),
            member.Id,
            member.ScopeId,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            Now.AddMinutes(-1)).Value;
        MemberMultiFactorFailureAttempt concurrentFailure = MemberMultiFactorFailureAttempt.Create(
            new MemberMultiFactorFailureAttemptId(Guid.NewGuid()),
            member.Id,
            member.ScopeId,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            Now).Value;
        dbContext.AddRange(member, authenticator, priorFailure, concurrentFailure);
        await dbContext.SaveChangesAsync();
        member.ClearDomainEvents();
        RecordingTokenService tokenService = new();
        RecordingAttemptLimiter attemptLimiter = new();

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            tokenService,
            attemptLimiter).HandleAsync(
                CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode),
                CancellationToken.None);
        await dbContext.SaveChangesAsync();

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Succeeded);
        Assert.False(result.Value.RefreshTokenReuseDetected);
        Assert.Equal("new-refresh", result.Value.Response!.RefreshToken);
        Assert.Equal("hash:new-refresh", session.RefreshTokenHash);
        Assert.Equal(AuthenticationContextReferences.MultiFactor, session.AuthenticationContextReference);
        Assert.Equal(
            [AuthenticationMethodReferences.Password, AuthenticationMethodReferences.OneTimePassword, AuthenticationMethodReferences.MultiFactor],
            session.AuthenticationMethodReferences);
        Assert.Equal(Now, session.AuthenticatedAtUtc);
        Assert.Equal(AuthenticationContextReferences.MultiFactor, tokenService.Claims!.AuthenticationEvidence.ContextReference);
        Assert.Contains(member.DomainEvents, item => item is MemberSessionReauthenticatedDomainEvent);
        Assert.Contains(attemptLimiter.AcquiredPurposes, purpose =>
            string.Equals(purpose, AuthenticationAttemptPurposes.PasswordStepUp, StringComparison.Ordinal));
        Assert.Contains(attemptLimiter.AcquiredPurposes, purpose =>
            string.Equals(purpose, AuthenticationAttemptPurposes.MultiFactorStepUp, StringComparison.Ordinal));
        Assert.Contains(attemptLimiter.SucceededPurposes, purpose =>
            string.Equals(purpose, AuthenticationAttemptPurposes.PasswordStepUp, StringComparison.Ordinal));
        Assert.Contains(attemptLimiter.SucceededPurposes, purpose =>
            string.Equals(purpose, AuthenticationAttemptPurposes.MultiFactorStepUp, StringComparison.Ordinal));
        Assert.Equal(1, await new MemberMultiFactorFailureAttemptRepository(dbContext).CountSinceAsync(
            member.Id,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            Now.AddMinutes(-15),
            CancellationToken.None));
    }

    [Fact]
    public async Task Wrong_password_and_wrong_factor_are_opaque_and_do_not_upgrade_the_session()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now.AddHours(-1),
            authenticationEvidence: SessionAuthenticationEvidence.Password(Now.AddHours(-1))).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        MemberMultiFactorFailureAttemptRepository failureRepository = new(dbContext);

        Result<MultiFactorStepUpCompletion> wrongPassword = await CreateHandler(dbContext).HandleAsync(
            CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode) with
            {
                Password = "wrong-password"
            },
            CancellationToken.None);
        Result<MultiFactorStepUpCompletion> wrongFactor = await CreateHandler(dbContext).HandleAsync(
            CreateCommand(member, session, MultiFactorCodeType.Totp, "wrong-code"),
            CancellationToken.None);
        await dbContext.SaveChangesAsync();

        Assert.True(wrongPassword.IsSuccess);
        Assert.False(wrongPassword.Value.Succeeded);
        Assert.True(wrongFactor.IsSuccess);
        Assert.False(wrongFactor.Value.Succeeded);
        Assert.Equal("hash:old-refresh", session.RefreshTokenHash);
        Assert.Equal(AuthenticationContextReferences.Password, session.AuthenticationContextReference);
        Assert.Equal(Now.AddHours(-1), session.AuthenticatedAtUtc);
        Assert.Equal(41, authenticator.LastAcceptedTimeStep);
        Assert.Equal(1, await failureRepository.CountSinceAsync(
            member.Id,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            Now.AddMinutes(-15),
            CancellationToken.None));
        Assert.Empty(member.DomainEvents.OfType<MemberSessionReauthenticatedDomainEvent>());
    }

    [Fact]
    public async Task Recovery_code_step_up_works_without_the_totp_provider_and_establishes_password_mfa()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now.AddHours(-4),
            authenticationEvidence: SessionAuthenticationEvidence.Password(Now.AddHours(-4))).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            totpProviderAvailable: false).HandleAsync(
            CreateCommand(member, session, MultiFactorCodeType.RecoveryCode, "RECOVERY-0"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Succeeded);
        Assert.Equal(9, authenticator.UnusedRecoveryCodeCount);
        Assert.Equal(AuthenticationContextReferences.MultiFactor, session.AuthenticationContextReference);
        Assert.Equal(
            [AuthenticationMethodReferences.Password, AuthenticationMethodReferences.RecoveryCode, AuthenticationMethodReferences.MultiFactor],
            session.AuthenticationMethodReferences);
    }

    [Fact]
    public async Task Replayed_refresh_token_revokes_all_sessions_before_reusing_the_factor()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession steppedUpSession = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now.AddHours(-1)).Value;
        MemberSession otherSession = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:other-refresh",
            Now.AddDays(1),
            Now.AddHours(-1)).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        var totpProvider = new FakeTotpProvider(isAvailable: true);
        StepUpWithMultiFactorCommandHandler handler = CreateHandler(dbContext, totpProvider: totpProvider);
        StepUpWithMultiFactorCommand command = CreateCommand(
            member,
            steppedUpSession,
            MultiFactorCodeType.Totp,
            FakeTotpProvider.ValidCode);

        Assert.True((await handler.HandleAsync(command, CancellationToken.None)).Value.Succeeded);
        member.ClearDomainEvents();
        Result<MultiFactorStepUpCompletion> replay = await handler.HandleAsync(
            command,
            CancellationToken.None);

        Assert.True(replay.IsSuccess);
        Assert.False(replay.Value.Succeeded);
        Assert.True(replay.Value.RefreshTokenReuseDetected);
        Assert.False(steppedUpSession.IsActive);
        Assert.False(otherSession.IsActive);
        Assert.Equal(42, authenticator.LastAcceptedTimeStep);
        Assert.Equal(1, totpProvider.VerificationCount);
        Assert.IsType<MemberSessionsRevokedDomainEvent>(
            Assert.Single(member.DomainEvents.OfType<MemberSessionsRevokedDomainEvent>()));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Invalid_or_expired_refresh_proof_is_rejected_before_password_or_factor(
        bool expired)
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            expired ? Now.AddMinutes(-1) : Now.AddDays(1),
            Now.AddHours(-2)).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        var limiter = new RecordingAttemptLimiter();
        var totpProvider = new FakeTotpProvider(isAvailable: true);
        StepUpWithMultiFactorCommand command = CreateCommand(
            member,
            session,
            MultiFactorCodeType.Totp,
            FakeTotpProvider.ValidCode) with
        {
            RefreshToken = expired ? "old-refresh" : "not-the-refresh-token"
        };

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            attemptLimiter: limiter,
            totpProvider: totpProvider).HandleAsync(command, CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(
            expired ? AuthApplicationErrors.RefreshTokenExpired : AuthApplicationErrors.SessionNotFound,
            result.Error);
        Assert.Empty(limiter.AcquiredPurposes);
        Assert.Equal(0, totpProvider.VerificationCount);
        Assert.Equal(41, authenticator.LastAcceptedTimeStep);
        Assert.Equal("hash:old-refresh", session.RefreshTokenHash);
    }

    [Fact]
    public async Task Factor_attempt_limiter_denial_is_opaque_and_does_not_mutate_factor_or_session()
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
        var limiter = new RecordingAttemptLimiter(AuthenticationAttemptPurposes.MultiFactorStepUp);
        var totpProvider = new FakeTotpProvider(isAvailable: true);
        MemberMultiFactorFailureAttemptRepository failureRepository = new(dbContext);

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            attemptLimiter: limiter,
            totpProvider: totpProvider).HandleAsync(
                CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode),
                CancellationToken.None);
        await dbContext.SaveChangesAsync();

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.Succeeded);
        Assert.False(result.Value.RefreshTokenReuseDetected);
        Assert.Equal(0, totpProvider.VerificationCount);
        Assert.Equal(41, authenticator.LastAcceptedTimeStep);
        Assert.Equal("hash:old-refresh", session.RefreshTokenHash);
        Assert.Equal(0, await failureRepository.CountSinceAsync(
            member.Id,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            Now.AddMinutes(-15),
            CancellationToken.None));
    }

    [Fact]
    public async Task Refresh_expiry_during_dependency_work_is_rechecked_before_factor_consumption()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddMinutes(1),
            Now.AddHours(-1)).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        var clock = new MutableClock(Now);
        var totpProvider = new FakeTotpProvider(isAvailable: true);
        IMemberTotpAuthenticatorRepository authenticatorRepository = new AdvancingAuthenticatorRepository(
            new MemberTotpAuthenticatorRepository(dbContext),
            clock,
            Now.AddMinutes(2));

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            totpProvider: totpProvider,
            authenticatorRepository: authenticatorRepository,
            clock: clock).HandleAsync(
                CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode),
                CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.RefreshTokenExpired, result.Error);
        Assert.Equal(0, totpProvider.VerificationCount);
        Assert.Equal(41, authenticator.LastAcceptedTimeStep);
        Assert.Equal("hash:old-refresh", session.RefreshTokenHash);
        Assert.Empty(member.DomainEvents.OfType<MemberSessionReauthenticatedDomainEvent>());
    }

    [Fact]
    public async Task Step_up_rechecks_refresh_expiry_after_factor_verification()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddMinutes(1),
            Now.AddHours(-1)).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        var clock = new MutableClock(Now);
        var totpProvider = new FakeTotpProvider(
            isAvailable: true,
            onVerify: () => clock.UtcNow = Now.AddMinutes(2));

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            totpProvider: totpProvider,
            clock: clock).HandleAsync(
                CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode),
                CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.RefreshTokenExpired, result.Error);
        Assert.Equal("hash:old-refresh", session.RefreshTokenHash);
        Assert.Equal(Now.AddHours(-1), session.AuthenticatedAtUtc);
        Assert.Empty(member.DomainEvents.OfType<MemberSessionReauthenticatedDomainEvent>());
    }

    [Fact]
    public async Task Successful_step_up_records_the_factor_completion_time()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now.AddHours(-1)).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();
        var clock = new MutableClock(Now);
        DateTimeOffset completedAtUtc = Now.AddSeconds(30);
        var tokenService = new RecordingTokenService();
        var totpProvider = new FakeTotpProvider(
            isAvailable: true,
            onVerify: () => clock.UtcNow = completedAtUtc);

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            tokenService: tokenService,
            totpProvider: totpProvider,
            clock: clock).HandleAsync(
                CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode),
                CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Succeeded);
        Assert.Equal(completedAtUtc, session.AuthenticatedAtUtc);
        Assert.Equal(completedAtUtc, tokenService.Claims!.AuthenticationEvidence.AuthenticatedAtUtc);
    }

    [Fact]
    public async Task External_only_member_is_told_that_password_step_up_is_unavailable()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = Member.CreateExternal(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "external@example.com",
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            "provider-subject",
            Guid.NewGuid(),
            Now.AddDays(-1)).Value;
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "hash:old-refresh",
            Now.AddDays(1),
            Now,
            MemberAuthenticationMethods.External("google"),
            SessionAuthenticationEvidence.External(Now)).Value;
        MemberTotpAuthenticator authenticator = CreateActiveAuthenticator(member);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(dbContext).HandleAsync(
            CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.PasswordNotConfigured, result.Error);
        Assert.Equal(AuthenticationContextReferences.External, session.AuthenticationContextReference);
        Assert.Equal(41, authenticator.LastAcceptedTimeStep);
    }

    [Fact]
    public async Task Provider_unavailability_does_not_rotate_or_record_an_invalid_factor()
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

        Result<MultiFactorStepUpCompletion> result = await CreateHandler(
            dbContext,
            totpProviderAvailable: false).HandleAsync(
                CreateCommand(member, session, MultiFactorCodeType.Totp, FakeTotpProvider.ValidCode),
                CancellationToken.None);
        await dbContext.SaveChangesAsync();

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.MultiFactorProviderUnavailable, result.Error);
        Assert.Equal("hash:old-refresh", session.RefreshTokenHash);
        Assert.Equal(0, await failureRepository.CountSinceAsync(
            member.Id,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            Now.AddMinutes(-15),
            CancellationToken.None));
    }

    private static StepUpWithMultiFactorCommand CreateCommand(
        Member member,
        MemberSession session,
        MultiFactorCodeType codeType,
        string code) =>
        new(member.Id.Value, session.Id.Value, Password, codeType, code, "old-refresh");

    private static StepUpWithMultiFactorCommandHandler CreateHandler(
        AuthDbContext dbContext,
        RecordingTokenService? tokenService = null,
        RecordingAttemptLimiter? attemptLimiter = null,
        bool totpProviderAvailable = true,
        FakeTotpProvider? totpProvider = null,
        IMemberTotpAuthenticatorRepository? authenticatorRepository = null,
        ISystemClock? clock = null)
    {
        var limiter = attemptLimiter ?? new RecordingAttemptLimiter();
        var options = Options.Create(new AuthApplicationOptions());
        ISystemClock effectiveClock = clock ?? new FakeClock();
        return new StepUpWithMultiFactorCommandHandler(
            new MemberRepository(dbContext),
            authenticatorRepository ?? new MemberTotpAuthenticatorRepository(dbContext),
            new MemberMultiFactorFailureAttemptRepository(dbContext),
            new FakePasswordHashingService(),
            new PasswordProofService(new FakePasswordHashingService(), limiter, options),
            CreateMultiFactorService(
                dbContext,
                totpProvider ?? new FakeTotpProvider(totpProviderAvailable),
                totpProviderAvailable,
                effectiveClock),
            limiter,
            tokenService ?? new RecordingTokenService(),
            new FakeRefreshTokenHashingService(),
            options,
            new TestScopeContext(),
            effectiveClock,
            new RandomIdGenerator());
    }

    private static AuthDbContext CreateDbContext() => new(
        new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-mfa-step-up-{Guid.NewGuid():N}")
            .Options,
        new TestScopeContext());

    private static Member CreateMember() => Member.Create(
        new MemberId(Guid.NewGuid()),
        "tenant-a",
        "member@example.com",
        MemberUsernameType.Email,
        $"hash:{Password}",
        new MemberUsernameId(Guid.NewGuid()),
        Guid.NewGuid(),
        Now.AddDays(-1)).Value;

    private static MemberTotpAuthenticator CreateActiveAuthenticator(Member member)
    {
        MemberTotpAuthenticator authenticator = MemberTotpAuthenticator.BeginEnrollment(
            new MemberTotpAuthenticatorId(Guid.NewGuid()),
            member.Id,
            member.ScopeId,
            "protected-secret",
            Now.AddMinutes(10),
            Now).Value;
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

    private static MultiFactorAuthenticationService CreateMultiFactorService(
        AuthDbContext dbContext,
        FakeTotpProvider totpProvider,
        bool secretProtectorAvailable,
        ISystemClock clock) =>
        new(
            new MemberTotpAuthenticatorRepository(dbContext),
            new MemberAuthenticationChallengeRepository(dbContext),
            new NoOpAuthenticationChallengeRequestSerializer(),
            totpProvider,
            new FakeSecretProtector(secretProtectorAvailable),
            new FakeMultiFactorTokenService(),
            Options.Create(new AuthApplicationOptions()),
            clock,
            new RandomIdGenerator());

    private sealed class FakePasswordHashingService : IPasswordHashingService
    {
        public string HashPassword(string password) => $"hash:{password}";
        public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password) =>
            string.Equals(passwordHash, this.HashPassword(password), StringComparison.Ordinal)
                ? PasswordVerificationOutcome.Success
                : PasswordVerificationOutcome.Unknown;
    }

    private sealed class FakeTotpProvider(bool isAvailable, Action? onVerify = null)
        : ITimeBasedOneTimePasswordProvider
    {
        public const string ValidCode = "123456";
        public bool IsAvailable => isAvailable;
        public int VerificationCount { get; private set; }
        public GeneratedTotpSecret GenerateSecret() => new([1, 2, 3, 4], "AEBAGBA");
        public string CreateProvisioningUri(string accountName, string encodedSecret) =>
            $"otpauth://totp/GMA:{accountName}?secret={encodedSecret}";
        public TotpVerificationResult Verify(byte[] secret, string code, DateTimeOffset nowUtc)
        {
            this.VerificationCount++;
            onVerify?.Invoke();
            return string.Equals(code, ValidCode, StringComparison.Ordinal)
                ? new TotpVerificationResult(true, 42)
                : TotpVerificationResult.Invalid;
        }
    }

    private sealed class FakeSecretProtector(bool isAvailable) : IAuthenticatorSecretProtector
    {
        public bool IsAvailable => isAvailable;
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

    private sealed class AdvancingAuthenticatorRepository(
        IMemberTotpAuthenticatorRepository inner,
        MutableClock clock,
        DateTimeOffset nextUtc)
        : IMemberTotpAuthenticatorRepository
    {
        public async Task<MemberTotpAuthenticator?> GetByMemberAsync(
            MemberId memberId,
            CancellationToken cancellationToken)
        {
            MemberTotpAuthenticator? authenticator = await inner
                .GetByMemberAsync(memberId, cancellationToken)
                .ConfigureAwait(false);
            clock.UtcNow = nextUtc;
            return authenticator;
        }

        public Task AddAsync(MemberTotpAuthenticator authenticator, CancellationToken cancellationToken) =>
            inner.AddAsync(authenticator, cancellationToken);
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

    private sealed class RecordingAttemptLimiter(string? deniedPurpose = null) : IAuthenticationAttemptLimiter
    {
        public List<string> AcquiredPurposes { get; } = [];
        public List<string> SucceededPurposes { get; } = [];

        public ValueTask<AuthenticationAttemptLease?> TryAcquireAsync(
            string scopeId,
            string purpose,
            string target,
            DateTimeOffset nowUtc,
            AuthenticationAttemptPolicy policy,
            CancellationToken cancellationToken)
        {
            this.AcquiredPurposes.Add(purpose);
            return ValueTask.FromResult<AuthenticationAttemptLease?>(string.Equals(
                purpose,
                deniedPurpose,
                StringComparison.Ordinal)
                    ? null
                    : new AuthenticationAttemptLease(Guid.NewGuid(), nowUtc));
        }

        public ValueTask RecordSuccessAsync(
            string scopeId,
            string purpose,
            string target,
            AuthenticationAttemptLease lease,
            CancellationToken cancellationToken)
        {
            this.SucceededPurposes.Add(purpose);
            return ValueTask.CompletedTask;
        }
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
