namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.ValueObjects;
using Xunit;

[Trait("Category", "Unit")]
public sealed class MemberAuthenticationChallengeTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Challenge_consumes_once_and_preserves_primary_evidence()
    {
        MemberAuthenticationChallenge challenge = CreateChallenge();

        var consumed = challenge.Consume("token-hash", Now.AddMinutes(1));
        var replay = challenge.Consume("token-hash", Now.AddMinutes(2));

        Assert.True(consumed.IsSuccess);
        Assert.Equal(AuthDomainErrors.AuthenticationChallengeInvalid, replay.Error);
        Assert.Equal(AuthenticationContextReferences.Password, challenge.PrimaryEvidence.ContextReference);
        Assert.Equal([AuthenticationMethodReferences.Password], challenge.PrimaryEvidence.MethodReferences);
    }

    [Fact]
    public void Failed_attempt_limit_revokes_challenge()
    {
        MemberAuthenticationChallenge challenge = CreateChallenge(maximumAttempts: 2);

        var first = challenge.RecordFailure(Now.AddSeconds(1));
        var second = challenge.RecordFailure(Now.AddSeconds(2));

        Assert.Equal(AuthDomainErrors.AuthenticationChallengeInvalid, first.Error);
        Assert.Equal(AuthDomainErrors.AuthenticationChallengeInvalid, second.Error);
        Assert.Equal(2, challenge.FailedAttemptCount);
        Assert.NotNull(challenge.RevokedAtUtc);
        Assert.False(challenge.IsActiveAt(Now.AddSeconds(3)));
    }

    [Fact]
    public void Challenge_rejects_expiration_wrong_hash_and_inconsistent_primary_evidence()
    {
        MemberAuthenticationChallenge challenge = CreateChallenge();
        var wrongHash = challenge.Consume("wrong", Now.AddMinutes(1));
        var expired = challenge.Consume("token-hash", Now.AddMinutes(6));
        var inconsistent = MemberAuthenticationChallenge.Create(
            new MemberAuthenticationChallengeId(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")),
            new MemberId(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff")),
            "tenant-a",
            "token-hash",
            MemberAuthenticationMethods.Password,
            SessionAuthenticationEvidence.External(Now),
            null,
            null,
            5,
            Now.AddMinutes(5),
            Now);

        Assert.Equal(AuthDomainErrors.AuthenticationChallengeInvalid, wrongHash.Error);
        Assert.Equal(AuthDomainErrors.AuthenticationChallengeInvalid, expired.Error);
        Assert.Equal(AuthDomainErrors.AuthenticationChallengeNotValid, inconsistent.Error);
    }

    [Fact]
    public void Combined_evidence_distinguishes_mfa_from_external_two_step()
    {
        SessionAuthenticationEvidence passwordTotp = SessionAuthenticationEvidence.CompleteWithTotp(
            SessionAuthenticationEvidence.Password(Now),
            Now.AddMinutes(1));
        SessionAuthenticationEvidence externalTotp = SessionAuthenticationEvidence.CompleteWithTotp(
            SessionAuthenticationEvidence.External(Now),
            Now.AddMinutes(1));
        SessionAuthenticationEvidence passwordRecovery = SessionAuthenticationEvidence.CompleteWithRecoveryCode(
            SessionAuthenticationEvidence.Password(Now),
            Now.AddMinutes(1));

        Assert.Equal(AuthenticationContextReferences.MultiFactor, passwordTotp.ContextReference);
        Assert.Equal(
            [AuthenticationMethodReferences.Password, AuthenticationMethodReferences.OneTimePassword, AuthenticationMethodReferences.MultiFactor],
            passwordTotp.MethodReferences);
        Assert.Equal(AuthenticationContextReferences.TwoStep, externalTotp.ContextReference);
        Assert.Equal(
            [AuthenticationMethodReferences.External, AuthenticationMethodReferences.OneTimePassword],
            externalTotp.MethodReferences);
        Assert.Equal(
            [AuthenticationMethodReferences.Password, AuthenticationMethodReferences.RecoveryCode, AuthenticationMethodReferences.MultiFactor],
            passwordRecovery.MethodReferences);
    }

    private static MemberAuthenticationChallenge CreateChallenge(int maximumAttempts = 5) =>
        MemberAuthenticationChallenge.Create(
            new MemberAuthenticationChallengeId(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")),
            new MemberId(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff")),
            "tenant-a",
            "token-hash",
            MemberAuthenticationMethods.Password,
            SessionAuthenticationEvidence.Password(Now),
            "127.0.0.1",
            "test-agent",
            maximumAttempts,
            Now.AddMinutes(5),
            Now).Value;
}
