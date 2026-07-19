namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Handlers;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class PasswordRecoveryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Challenge_has_an_independent_one_time_lifecycle()
    {
        Result<PasswordRecoveryChallenge> created = PasswordRecoveryChallenge.Create(
            new PasswordRecoveryChallengeId(Guid.NewGuid()),
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "member@example.com",
            "hash:recovery-code",
            "recovery-code",
            Guid.NewGuid(),
            Now.AddMinutes(30),
            Now);

        Assert.True(created.IsSuccess);
        PasswordRecoveryChallenge challenge = created.Value;
        Assert.True(challenge.IsActiveAt(Now));
        Assert.IsType<MemberPasswordRecoveryRequestedDomainEvent>(Assert.Single(challenge.DomainEvents));
        Assert.True(challenge.Consume("hash:wrong-code", Now.AddSeconds(30)).IsFailure);
        Assert.True(challenge.IsActiveAt(Now.AddSeconds(30)));
        Assert.True(challenge.Consume("hash:recovery-code", Now.AddMinutes(1)).IsSuccess);
        Assert.False(challenge.IsActiveAt(Now.AddMinutes(1)));
        Assert.True(challenge.Consume("hash:recovery-code", Now.AddMinutes(2)).IsFailure);
    }

    [Fact]
    public void Challenge_rejects_expired_and_revoked_codes()
    {
        PasswordRecoveryChallenge expired = CreateChallenge(
            new MemberId(Guid.NewGuid()),
            "hash:expired-code",
            "expired-code");
        PasswordRecoveryChallenge revoked = CreateChallenge(
            new MemberId(Guid.NewGuid()),
            "hash:revoked-code",
            "revoked-code");

        revoked.Revoke(Now.AddMinutes(1));

        Assert.False(expired.IsActiveAt(Now.AddMinutes(30)));
        Assert.True(expired.Consume("hash:expired-code", Now.AddMinutes(30)).IsFailure);
        Assert.False(revoked.IsActiveAt(Now.AddMinutes(2)));
        Assert.True(revoked.Consume("hash:revoked-code", Now.AddMinutes(2)).IsFailure);
    }

    [Fact]
    public async Task Unknown_and_ineligible_accounts_receive_the_same_success_without_a_challenge()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member unverified = CreatePasswordMember("unverified@example.com");
        Member externalOnly = Member.CreateExternal(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "external@example.com",
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            "external-subject",
            Guid.NewGuid(),
            Now).Value;
        Member disabled = CreateVerifiedPasswordMember("disabled@example.com");
        Assert.True(disabled.Disable("security hold", Guid.NewGuid(), Now.AddMinutes(1)).IsSuccess);
        dbContext.Members.AddRange(unverified, externalOnly, disabled);
        await dbContext.SaveChangesAsync();
        RequestPasswordRecoveryCommandHandler handler = CreateRequestHandler(dbContext);

        Result<Unit> unknown = await handler.HandleAsync(
            new RequestPasswordRecoveryCommand("unknown@example.com"),
            CancellationToken.None);
        Result<Unit> unverifiedResult = await handler.HandleAsync(
            new RequestPasswordRecoveryCommand("unverified@example.com"),
            CancellationToken.None);
        Result<Unit> externalResult = await handler.HandleAsync(
            new RequestPasswordRecoveryCommand("external@example.com"),
            CancellationToken.None);
        Result<Unit> disabledResult = await handler.HandleAsync(
            new RequestPasswordRecoveryCommand("disabled@example.com"),
            CancellationToken.None);

        Assert.True(unknown.IsSuccess);
        Assert.True(unverifiedResult.IsSuccess);
        Assert.True(externalResult.IsSuccess);
        Assert.True(disabledResult.IsSuccess);
        Assert.Empty(dbContext.PasswordRecoveryChallenges);
    }

    [Fact]
    public async Task Eligible_request_creates_one_challenge_and_durable_cooldown_suppresses_a_repeat()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateVerifiedPasswordMember();
        dbContext.Members.Add(member);
        await dbContext.SaveChangesAsync();
        RequestPasswordRecoveryCommandHandler handler = CreateRequestHandler(dbContext);

        Result<Unit> first = await handler.HandleAsync(
            new RequestPasswordRecoveryCommand(" MEMBER@example.com "),
            CancellationToken.None);
        await dbContext.SaveChangesAsync();
        Result<Unit> second = await handler.HandleAsync(
            new RequestPasswordRecoveryCommand("member@example.com"),
            CancellationToken.None);
        await dbContext.SaveChangesAsync();

        Assert.True(first.IsSuccess);
        Assert.True(second.IsSuccess);
        PasswordRecoveryChallenge challenge = Assert.Single(dbContext.PasswordRecoveryChallenges);
        MemberPasswordRecoveryRequestedDomainEvent requested = Assert.IsType<MemberPasswordRecoveryRequestedDomainEvent>(
            Assert.Single(challenge.DomainEvents));
        Assert.Equal("member@example.com", requested.Email);
    }

    [Fact]
    public async Task Eligible_request_after_the_cooldown_revokes_the_previous_challenge()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateVerifiedPasswordMember();
        PasswordRecoveryChallenge previous = CreateChallenge(
            member.Id,
            "hash:previous-code",
            "previous-code");
        dbContext.AddRange(member, previous);
        await dbContext.SaveChangesAsync();

        Result<Unit> result = await CreateRequestHandler(dbContext).HandleAsync(
            new RequestPasswordRecoveryCommand("member@example.com"),
            CancellationToken.None);
        await dbContext.SaveChangesAsync();

        Assert.True(result.IsSuccess);
        Assert.NotNull(previous.RevokedAtUtc);
        PasswordRecoveryChallenge[] challenges = [.. dbContext.PasswordRecoveryChallenges];
        Assert.Equal(2, challenges.Length);
        Assert.Single(challenges, challenge => challenge.IsActiveAt(Now.AddMinutes(2)));
    }

    [Fact]
    public async Task Confirmation_resets_password_revokes_sessions_and_rejects_replay()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateVerifiedPasswordMember();
        MemberSession session = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "refresh-hash",
            Now.AddDays(1),
            Now).Value;
        MemberTotpAuthenticator authenticator = MemberTotpAuthenticator.BeginEnrollment(
            new MemberTotpAuthenticatorId(Guid.NewGuid()),
            member.Id,
            member.ScopeId,
            "protected-secret",
            Now.AddMinutes(10),
            Now).Value;
        Assert.True(authenticator.Activate(
            42,
            [new TotpRecoveryCodeRegistration(new MemberTotpRecoveryCodeId(Guid.NewGuid()), "recovery-hash")],
            Now).IsSuccess);
        dbContext.AddRange(member, authenticator);
        await dbContext.SaveChangesAsync();

        RequestPasswordRecoveryCommandHandler requestHandler = CreateRequestHandler(dbContext);
        await requestHandler.HandleAsync(
            new RequestPasswordRecoveryCommand("member@example.com"),
            CancellationToken.None);
        await dbContext.SaveChangesAsync();
        PasswordRecoveryChallenge challenge = Assert.Single(dbContext.PasswordRecoveryChallenges);
        PasswordRecoveryChallenge otherChallenge = PasswordRecoveryChallenge.Create(
            new PasswordRecoveryChallengeId(Guid.NewGuid()),
            member.Id,
            member.ScopeId,
            "member@example.com",
            "hash:other-recovery-code",
            "other-recovery-code",
            Guid.NewGuid(),
            Now.AddMinutes(30),
            Now.AddMinutes(1)).Value;
        dbContext.PasswordRecoveryChallenges.Add(otherChallenge);
        await dbContext.SaveChangesAsync();
        member.ClearDomainEvents();

        var confirmHandler = new ConfirmPasswordRecoveryCommandHandler(
            new PasswordRecoveryChallengeRepository(dbContext),
            new MemberRepository(dbContext),
            new FakeRecoveryTokenService(),
            new FakePasswordHashingService(),
            new AllowAllPasswordBlocklist(),
            new FakeClock(),
            new RandomIdGenerator());
        ConfirmPasswordRecoveryCommand command = new(
            FakeRecoveryTokenService.Code,
            "NewSafePassword123!");

        Result<Unit> wrongCode = await confirmHandler.HandleAsync(
            command with { Code = "wrong-recovery-code" },
            CancellationToken.None);
        Result<Unit> confirmed = await confirmHandler.HandleAsync(command, CancellationToken.None);
        await dbContext.SaveChangesAsync();
        Result<Unit> replay = await confirmHandler.HandleAsync(command, CancellationToken.None);

        Assert.True(wrongCode.IsFailure);
        Assert.Equal(AuthApplicationErrors.PasswordRecoveryInvalid, wrongCode.Error);
        Assert.True(confirmed.IsSuccess);
        Assert.False(session.IsActive);
        Assert.Equal("hash:NewSafePassword123!", member.PasswordHash);
        Assert.True(authenticator.IsActive);
        Assert.Equal(1, authenticator.UnusedRecoveryCodeCount);
        Assert.NotNull(challenge.ConsumedAtUtc);
        Assert.NotNull(otherChallenge.RevokedAtUtc);
        Assert.Contains(member.DomainEvents, domainEvent => domainEvent is MemberSessionsRevokedDomainEvent);
        Assert.Contains(member.DomainEvents, domainEvent => domainEvent is MemberAuthenticationMethodChangedDomainEvent);
        Assert.True(replay.IsFailure);
        Assert.Equal(AuthApplicationErrors.PasswordRecoveryInvalid, replay.Error);
    }

    [Fact]
    public async Task Confirmation_applies_the_compromised_password_blocklist_before_mutation()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        Member member = CreateVerifiedPasswordMember();
        dbContext.Members.Add(member);
        await dbContext.SaveChangesAsync();
        await CreateRequestHandler(dbContext).HandleAsync(
            new RequestPasswordRecoveryCommand("member@example.com"),
            CancellationToken.None);
        await dbContext.SaveChangesAsync();
        PasswordRecoveryChallenge challenge = Assert.Single(dbContext.PasswordRecoveryChallenges);
        string originalPasswordHash = member.PasswordHash!;
        var handler = new ConfirmPasswordRecoveryCommandHandler(
            new PasswordRecoveryChallengeRepository(dbContext),
            new MemberRepository(dbContext),
            new FakeRecoveryTokenService(),
            new FakePasswordHashingService(),
            new RejectAllPasswordBlocklist(),
            new FakeClock(),
            new RandomIdGenerator());

        Result<Unit> result = await handler.HandleAsync(
            new ConfirmPasswordRecoveryCommand(FakeRecoveryTokenService.Code, "CompromisedPassword123!"),
            CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthApplicationErrors.PasswordBlocked, result.Error);
        Assert.Equal(originalPasswordHash, member.PasswordHash);
        Assert.True(challenge.IsActiveAt(Now.AddMinutes(2)));
    }

    [Fact]
    public async Task Recovery_lookup_is_isolated_by_the_active_auth_scope()
    {
        string databaseName = $"auth-recovery-scope-{Guid.NewGuid():N}";
        DbContextOptions<AuthDbContext> options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName)
            .Options;
        await using (AuthDbContext tenantA = new(options, new TestScopeContext("tenant-a")))
        {
            tenantA.Members.Add(CreateVerifiedPasswordMember());
            await tenantA.SaveChangesAsync();
        }

        await using AuthDbContext tenantB = new(options, new TestScopeContext("tenant-b"));
        RequestPasswordRecoveryCommandHandler handler = CreateRequestHandler(tenantB);
        Result<Unit> result = await handler.HandleAsync(
            new RequestPasswordRecoveryCommand("member@example.com"),
            CancellationToken.None);
        await tenantB.SaveChangesAsync();

        Assert.True(result.IsSuccess);
        Assert.Empty(tenantB.PasswordRecoveryChallenges);
    }

    private static RequestPasswordRecoveryCommandHandler CreateRequestHandler(AuthDbContext dbContext) => new(
        new PasswordRecoveryRecipientReader(dbContext),
        new PasswordRecoveryChallengeRepository(dbContext),
        new FakeRecoveryTokenService(),
        new FakeClock(),
        new RandomIdGenerator(),
        Options.Create(new AuthApplicationOptions()));

    private static AuthDbContext CreateDbContext() => new(
        new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-password-recovery-{Guid.NewGuid():N}")
            .Options,
        new TestScopeContext("tenant-a"));

    private static Member CreateVerifiedPasswordMember(string emailAddress = "member@example.com")
    {
        Member member = CreatePasswordMember(emailAddress);
        MemberUsername username = Assert.Single(member.Usernames);
        Assert.True(member.RequestEmailVerification(
            username.Id,
            "verification-hash",
            "verification-code",
            Guid.NewGuid(),
            Now.AddHours(1),
            Now).IsSuccess);
        Assert.True(member.ConfirmEmailVerification(
            username.Id,
            "verification-hash",
            Guid.NewGuid(),
            Now.AddMinutes(1)).IsSuccess);
        member.ClearDomainEvents();
        return member;
    }

    private static Member CreatePasswordMember(string email) => Member.Create(
        new MemberId(Guid.NewGuid()),
        "tenant-a",
        email,
        MemberUsernameType.Email,
        "hash:CurrentPassword123!",
        new MemberUsernameId(Guid.NewGuid()),
        Guid.NewGuid(),
        Now).Value;

    private static PasswordRecoveryChallenge CreateChallenge(
        MemberId memberId,
        string tokenHash,
        string code) => PasswordRecoveryChallenge.Create(
            new PasswordRecoveryChallengeId(Guid.NewGuid()),
            memberId,
            "tenant-a",
            "member@example.com",
            tokenHash,
            code,
            Guid.NewGuid(),
            Now.AddMinutes(30),
            Now).Value;

    private sealed class FakeRecoveryTokenService : IPasswordRecoveryTokenService
    {
        public const string Code = "recovery-code";

        public string GenerateCode() => Code;
        public string HashCode(string code) => $"hash:{code}";
        public IReadOnlyList<string> GetCandidateHashes(string code) => [$"hash:{code}"];
    }

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

    private sealed class RejectAllPasswordBlocklist : IPasswordBlocklist
    {
        public ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken) =>
            ValueTask.FromResult(true);
    }

    private sealed class FakeClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now.AddMinutes(2);
    }

    private sealed class RandomIdGenerator : IIdGenerator
    {
        public Guid NewId() => Guid.NewGuid();
    }

    private sealed class TestScopeContext(string scopeId) : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => scopeId;
        public bool TryRestoreScope(string? restoredScopeId) =>
            string.Equals(this.ScopeId, restoredScopeId, StringComparison.Ordinal);
    }
}
