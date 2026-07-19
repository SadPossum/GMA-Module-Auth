namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Handlers;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class ExternalAuthenticationFlowTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Password_self_registration_can_be_disabled()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        var handler = new RegisterMemberCommandHandler(
            repository,
            new TestScopeContext(),
            new FakePasswordHashingService(),
            new AllowAllPasswordBlocklist(),
            new FakeTokenService("refresh-token"),
            new FakeHashingService(),
            Options.Create(CreateClosedRegistrationOptions()),
            new FakeClock(),
            new SequentialIdGenerator());

        Result<AuthTokensResponse> result = await handler.HandleAsync(
            new RegisterMemberCommand("member@example.com", UsernameType.Email, "safe-test-password"),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.SelfRegistrationDisabled, result.Error);
        Assert.Null(await repository.GetByUsernameAsync("member@example.com", CancellationToken.None));
    }

    [Fact]
    public async Task Verified_external_identity_creates_account_and_exchange_is_single_use()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        var store = new InMemoryExchangeStore();
        store.Add(CreateExchange(email: "member@example.com", emailVerified: true));
        var handler = CreateExchangeHandler(store, repository);

        Result<ExternalAuthenticationResponse> result = await handler.HandleAsync(
            new ExchangeExternalAuthenticationCommand("one-time-code", null, null, "203.0.113.10", "test-agent"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(ExternalAuthenticationStatus.Authenticated, result.Value.Status);
        await dbContext.SaveChangesAsync();
        Member member = Assert.IsType<Member>(await repository.GetByExternalIdentityAsync(
            "https://accounts.example.test",
            "provider-subject",
            CancellationToken.None));
        Assert.False(member.HasPassword);
        Assert.True(Assert.Single(member.Usernames).IsVerified);
        Assert.Equal("external:google", Assert.Single(member.Sessions).AuthenticationMethod);

        Result<ExternalAuthenticationResponse> replay = await handler.HandleAsync(
            new ExchangeExternalAuthenticationCommand("one-time-code", null, null),
            CancellationToken.None);
        Assert.True(replay.IsFailure);
        Assert.Equal(AuthApplicationErrors.ExternalExchangeInvalid, replay.Error);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("unverified@example.com", false)]
    public async Task External_registration_requires_provider_verified_email(string? email, bool emailVerified)
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        var store = new InMemoryExchangeStore();
        store.Add(CreateExchange(email, emailVerified));

        Result<ExternalAuthenticationResponse> result = await CreateExchangeHandler(store, repository).HandleAsync(
            new ExchangeExternalAuthenticationCommand("one-time-code", null, null),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.ExternalVerifiedEmailRequired, result.Error);
    }

    [Fact]
    public async Task External_self_registration_can_be_disabled()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        var store = new InMemoryExchangeStore();
        store.Add(CreateExchange("member@example.com", emailVerified: true));

        Result<ExternalAuthenticationResponse> result = await CreateExchangeHandler(
                store,
                repository,
                CreateClosedRegistrationOptions())
            .HandleAsync(
                new ExchangeExternalAuthenticationCommand("one-time-code", null, null),
                CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.SelfRegistrationDisabled, result.Error);
        Assert.Null(await repository.GetByExternalIdentityAsync(
            "https://accounts.example.test",
            "provider-subject",
            CancellationToken.None));
    }

    [Fact]
    public async Task Disabled_external_registration_does_not_block_an_existing_identity()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        Member existing = Member.CreateExternal(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "member@example.com",
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.example.test",
            "provider-subject",
            Guid.NewGuid(),
            Now).Value;
        await repository.AddAsync(existing, CancellationToken.None);
        await dbContext.SaveChangesAsync();
        var store = new InMemoryExchangeStore();
        store.Add(CreateExchange("member@example.com", emailVerified: true));

        Result<ExternalAuthenticationResponse> result = await CreateExchangeHandler(
                store,
                repository,
                CreateClosedRegistrationOptions())
            .HandleAsync(
                new ExchangeExternalAuthenticationCommand("one-time-code", null, null),
                CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(ExternalAuthenticationStatus.Authenticated, result.Value.Status);
    }

    [Fact]
    public async Task Existing_external_identity_with_active_totp_receives_a_challenge_and_no_session()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        Member existing = Member.CreateExternal(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "member@example.com",
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.example.test",
            "provider-subject",
            Guid.NewGuid(),
            Now).Value;
        MemberTotpAuthenticator authenticator = MemberTotpAuthenticator.BeginEnrollment(
            new MemberTotpAuthenticatorId(Guid.NewGuid()),
            existing.Id,
            existing.ScopeId,
            "protected-secret",
            Now.AddMinutes(10),
            Now).Value;
        Assert.True(authenticator.Activate(
            42,
            [new TotpRecoveryCodeRegistration(new MemberTotpRecoveryCodeId(Guid.NewGuid()), "recovery-hash")],
            Now).IsSuccess);
        await repository.AddAsync(existing, CancellationToken.None);
        dbContext.MemberTotpAuthenticators.Add(authenticator);
        await dbContext.SaveChangesAsync();
        var store = new InMemoryExchangeStore();
        store.Add(CreateExchange("member@example.com", emailVerified: true));

        Result<ExternalAuthenticationResponse> result = await CreateExchangeHandler(
                store,
                repository,
                multiFactorService: CreateMultiFactorService(dbContext))
            .HandleAsync(
                new ExchangeExternalAuthenticationCommand("one-time-code", null, null),
                CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(ExternalAuthenticationStatus.MultiFactorRequired, result.Value.Status);
        Assert.NotNull(result.Value.MultiFactorChallenge);
        Assert.Null(result.Value.AccessToken);
        Assert.Null(result.Value.RefreshToken);
        Assert.Empty(existing.Sessions);
        Assert.Single(dbContext.MemberAuthenticationChallenges.Local);
    }

    [Fact]
    public async Task Existing_email_requires_explicit_authenticated_link_instead_of_auto_merge()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        Member existing = CreatePasswordMember("member@example.com");
        await repository.AddAsync(existing, CancellationToken.None);
        await dbContext.SaveChangesAsync();
        var store = new InMemoryExchangeStore();
        store.Add(CreateExchange("member@example.com", emailVerified: true));

        Result<ExternalAuthenticationResponse> result = await CreateExchangeHandler(store, repository).HandleAsync(
            new ExchangeExternalAuthenticationCommand("one-time-code", null, null),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.ExternalAccountLinkRequired, result.Error);
        Assert.Empty(existing.ExternalIdentities);
    }

    [Fact]
    public async Task Link_exchange_is_bound_to_the_exact_fresh_member_session()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        Member member = CreatePasswordMember("member@example.com");
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001")),
            "refresh-hash",
            Now.AddDays(1),
            Now).Value;
        await repository.AddAsync(member, CancellationToken.None);
        await dbContext.SaveChangesAsync();
        var store = new InMemoryExchangeStore();
        store.Add(CreateExchange(
            "member@example.com",
            emailVerified: true,
            ExternalAuthenticationIntent.Link,
            member.Id.Value,
            session.Id.Value));
        var handler = CreateExchangeHandler(store, repository);

        Result<ExternalAuthenticationResponse> wrongSession = await handler.HandleAsync(
            new ExchangeExternalAuthenticationCommand(
                "one-time-code",
                member.Id.Value,
                Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002")),
            CancellationToken.None);

        Assert.True(wrongSession.IsFailure);
        Assert.Equal(AuthApplicationErrors.ExternalLinkAuthorizationRequired, wrongSession.Error);
        Assert.Empty(member.ExternalIdentities);

        store.Add(CreateExchange(
            "member@example.com",
            emailVerified: true,
            ExternalAuthenticationIntent.Link,
            member.Id.Value,
            session.Id.Value,
            codeHash: Hash("second-code")));
        Result<ExternalAuthenticationResponse> linked = await handler.HandleAsync(
            new ExchangeExternalAuthenticationCommand("second-code", member.Id.Value, session.Id.Value),
            CancellationToken.None);

        Assert.True(linked.IsSuccess);
        Assert.Equal(ExternalAuthenticationStatus.Linked, linked.Value.Status);
        Assert.Equal("google", Assert.Single(member.ExternalIdentities).ProviderCode);
    }

    [Fact]
    public async Task Email_verification_persists_only_hash_and_clears_it_after_confirmation()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        Member member = CreatePasswordMember("member@example.com");
        await repository.AddAsync(member, CancellationToken.None);
        await dbContext.SaveChangesAsync();
        var tokenService = new FakeAuthOneTimeTokenService("verification-code");
        var clock = new FakeClock();
        var idGenerator = new SequentialIdGenerator();
        var requestHandler = new RequestEmailVerificationCommandHandler(
            repository,
            tokenService,
            clock,
            idGenerator,
            Options.Create(new AuthApplicationOptions()));

        Result request = await requestHandler.HandleAsync(
            new RequestEmailVerificationCommand(member.Id.Value, null),
            CancellationToken.None);

        Assert.True(request.IsSuccess);
        MemberUsername email = Assert.Single(member.Usernames);
        Assert.Equal(
            Hash($"{AuthOneTimeTokenPurpose.EmailVerification}:verification-code"),
            email.VerificationTokenHash);
        Assert.DoesNotContain("verification-code", email.VerificationTokenHash, StringComparison.OrdinalIgnoreCase);

        Result<Unit> repeatedRequest = await requestHandler.HandleAsync(
            new RequestEmailVerificationCommand(member.Id.Value, null),
            CancellationToken.None);
        Assert.True(repeatedRequest.IsFailure);
        Assert.Equal(AuthApplicationErrors.EmailVerificationRequestTooSoon, repeatedRequest.Error);
        await dbContext.SaveChangesAsync();

        var confirmationHandler = new ConfirmEmailVerificationCommandHandler(
            repository,
            tokenService,
            clock,
            idGenerator);
        Result confirmation = await confirmationHandler.HandleAsync(
            new ConfirmEmailVerificationCommand("verification-code"),
            CancellationToken.None);

        Assert.True(confirmation.IsSuccess);
        Assert.True(email.IsVerified);
        Assert.Null(email.VerificationTokenHash);
        Assert.Null(email.VerificationExpiresAtUtc);
    }

    private static ExchangeExternalAuthenticationCommandHandler CreateExchangeHandler(
        IExternalAuthenticationExchangeStore store,
        IMemberRepository repository,
        AuthApplicationOptions? options = null,
        MultiFactorAuthenticationService? multiFactorService = null) =>
        new(
            store,
            repository,
            multiFactorService ?? CreateMultiFactorService(),
            new FakeTokenService("refresh-token"),
            new FakeHashingService(),
            new FakeAuthOneTimeTokenService("one-time-code"),
            Options.Create(options ?? new AuthApplicationOptions()),
            new TestScopeContext(),
            new FakeClock(),
            new SequentialIdGenerator());

    private static MultiFactorAuthenticationService CreateMultiFactorService() =>
        new(
            new EmptyTotpAuthenticatorRepository(),
            new EmptyAuthenticationChallengeRepository(),
            new UnavailableTimeBasedOneTimePasswordProvider(),
            new UnavailableAuthenticatorSecretProtector(),
            new FakeMultiFactorTokenService(),
            Options.Create(new AuthApplicationOptions()),
            new FakeClock(),
            new SequentialIdGenerator());

    private static MultiFactorAuthenticationService CreateMultiFactorService(AuthDbContext dbContext) =>
        new(
            new MemberTotpAuthenticatorRepository(dbContext),
            new MemberAuthenticationChallengeRepository(dbContext),
            new UnavailableTimeBasedOneTimePasswordProvider(),
            new UnavailableAuthenticatorSecretProtector(),
            new FakeMultiFactorTokenService(),
            Options.Create(new AuthApplicationOptions()),
            new FakeClock(),
            new SequentialIdGenerator());

    private static AuthApplicationOptions CreateClosedRegistrationOptions() =>
        new()
        {
            SelfRegistration = new AuthSelfRegistrationOptions
            {
                PasswordEnabled = false,
                ExternalEnabled = false,
            },
        };

    private static ExternalAuthenticationExchange CreateExchange(
        string? email,
        bool emailVerified,
        ExternalAuthenticationIntent intent = ExternalAuthenticationIntent.SignIn,
        Guid? targetMemberId = null,
        Guid? targetSessionId = null,
        string? codeHash = null) =>
        new(
            Guid.NewGuid(),
            "tenant-a",
            codeHash ?? Hash("one-time-code"),
            intent,
            "google",
            "https://accounts.example.test",
            "provider-subject",
            email,
            emailVerified,
            targetMemberId,
            targetSessionId,
            "/auth/complete",
            Now,
            Now.AddMinutes(5));

    private static AuthDbContext CreateDbContext()
    {
        DbContextOptions<AuthDbContext> options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-external-flow-{Guid.NewGuid():N}")
            .Options;
        return new AuthDbContext(options, new TestScopeContext());
    }

    private static Member CreatePasswordMember(string email) =>
        Member.Create(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            email,
            MemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            Now).Value;

    private static string Hash(string value) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));

    private sealed class InMemoryExchangeStore : IExternalAuthenticationExchangeStore
    {
        private readonly Dictionary<string, ExternalAuthenticationExchange> exchanges = new(StringComparer.Ordinal);

        public void Add(ExternalAuthenticationExchange exchange) => this.exchanges.Add(exchange.CodeHash, exchange);

        public Task AddAsync(ExternalAuthenticationExchange exchange, CancellationToken cancellationToken)
        {
            this.Add(exchange);
            return Task.CompletedTask;
        }

        public Task<ExternalAuthenticationExchange?> ConsumeAsync(
            string codeHash,
            DateTimeOffset consumedAtUtc,
            CancellationToken cancellationToken)
        {
            if (!this.exchanges.Remove(codeHash, out ExternalAuthenticationExchange? exchange) ||
                exchange.ExpiresAtUtc <= consumedAtUtc)
            {
                return Task.FromResult<ExternalAuthenticationExchange?>(null);
            }

            return Task.FromResult<ExternalAuthenticationExchange?>(exchange with { ConsumedAtUtc = consumedAtUtc });
        }

        public Task<int> DeleteExpiredAsync(
            DateTimeOffset cutoffUtc,
            int batchSize,
            CancellationToken cancellationToken)
        {
            string[] keys = this.exchanges
                .Where(item => item.Value.ExpiresAtUtc <= cutoffUtc)
                .Take(batchSize)
                .Select(item => item.Key)
                .ToArray();
            foreach (string key in keys)
            {
                this.exchanges.Remove(key);
            }

            return Task.FromResult(keys.Length);
        }
    }

    private sealed class EmptyTotpAuthenticatorRepository : IMemberTotpAuthenticatorRepository
    {
        public Task<MemberTotpAuthenticator?> GetByMemberAsync(
            MemberId memberId,
            CancellationToken cancellationToken) =>
            Task.FromResult<MemberTotpAuthenticator?>(null);

        public Task AddAsync(MemberTotpAuthenticator authenticator, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class EmptyAuthenticationChallengeRepository : IMemberAuthenticationChallengeRepository
    {
        public Task<MemberAuthenticationChallenge?> GetByTokenHashesAsync(
            IReadOnlyCollection<string> tokenHashes,
            CancellationToken cancellationToken) =>
            Task.FromResult<MemberAuthenticationChallenge?>(null);

        public Task<IReadOnlyList<MemberAuthenticationChallenge>> GetActiveByMemberAsync(
            MemberId memberId,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MemberAuthenticationChallenge>>([]);

        public Task AddAsync(MemberAuthenticationChallenge challenge, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class FakeMultiFactorTokenService : IMultiFactorTokenService
    {
        public MultiFactorTokenMaterial GenerateChallengeToken() => new("challenge", "challenge-hash");

        public IReadOnlyList<string> GetCandidateChallengeTokenHashes(string token) => ["challenge-hash"];

        public IReadOnlyList<RecoveryCodeMaterial> GenerateRecoveryCodes(int count) => [];

        public IReadOnlyList<string> GetCandidateRecoveryCodeHashes(string code) => [];
    }

    private sealed class FakeClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
    }

    private sealed class SequentialIdGenerator : IIdGenerator
    {
        private int sequence;

        public Guid NewId()
        {
            this.sequence++;
            return Guid.Parse($"00000000-0000-0000-0000-{this.sequence:D12}");
        }
    }

    private sealed class TestScopeContext : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => "tenant-a";
        public bool TryRestoreScope(string? scopeId) =>
            string.Equals(this.ScopeId, scopeId, StringComparison.Ordinal);
    }

    private sealed class FakeHashingService : IRefreshTokenHashingService
    {
        public string HashRefreshToken(string refreshToken) => Hash(refreshToken);
        public IReadOnlyList<string> GetCandidateHashes(string refreshToken) => [Hash(refreshToken)];
    }

    private sealed class FakeAuthOneTimeTokenService(string token) : IAuthOneTimeTokenService
    {
        public string GenerateToken() => token;

        public string HashToken(AuthOneTimeTokenPurpose purpose, string value) =>
            Hash($"{purpose}:{value}");

        public IReadOnlyList<string> GetCandidateHashes(AuthOneTimeTokenPurpose purpose, string value) =>
            [this.HashToken(purpose, value), Hash(value)];
    }

    private sealed class FakePasswordHashingService : IPasswordHashingService
    {
        public string HashPassword(string password) => $"hash:{password}";

        public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password) =>
            passwordHash == $"hash:{password}"
                ? PasswordVerificationOutcome.Success
                : PasswordVerificationOutcome.Unknown;
    }

    private sealed class AllowAllPasswordBlocklist : IPasswordBlocklist
    {
        public ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken) =>
            ValueTask.FromResult(false);
    }

    private sealed class FakeTokenService(string refreshToken) : ITokenService
    {
        public string GenerateAccessToken(AccessTokenClaims claims) =>
            $"access:{claims.MemberId.Value:D}:{claims.SessionId.Value:D}";

        public string GenerateRefreshToken() => refreshToken;
        public MemberId? GetMemberId(string accessToken, bool validateLifetime) => null;
        public AccessTokenClaims? GetAccessTokenClaims(string accessToken, bool validateLifetime) => null;
    }
}
