namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Domain;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthIdValueObjectTests
{
    [Fact]
    public void Member_id_requires_non_empty_value()
    {
        Guid value = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        Assert.Equal(value, new MemberId(value).Value);
        Assert.Throws<ArgumentException>(() => new MemberId(Guid.Empty));
    }

    [Fact]
    public void Member_username_id_requires_non_empty_value()
    {
        Guid value = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        Assert.Equal(value, new MemberUsernameId(value).Value);
        Assert.Throws<ArgumentException>(() => new MemberUsernameId(Guid.Empty));
    }

    [Fact]
    public void Member_session_id_requires_non_empty_value()
    {
        Guid value = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        Assert.Equal(value, new MemberSessionId(value).Value);
        Assert.Throws<ArgumentException>(() => new MemberSessionId(Guid.Empty));
    }

    [Fact]
    public void Mfa_ids_require_non_empty_values()
    {
        Guid value = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        Assert.Equal(value, new MemberTotpAuthenticatorId(value).Value);
        Assert.Equal(value, new MemberTotpRecoveryCodeId(value).Value);
        Assert.Equal(value, new MemberAuthenticationChallengeId(value).Value);
        Assert.Equal(value, new MemberMultiFactorFailureAttemptId(value).Value);
        Assert.Throws<ArgumentException>(() => new MemberTotpAuthenticatorId(Guid.Empty));
        Assert.Throws<ArgumentException>(() => new MemberTotpRecoveryCodeId(Guid.Empty));
        Assert.Throws<ArgumentException>(() => new MemberAuthenticationChallengeId(Guid.Empty));
        Assert.Throws<ArgumentException>(() => new MemberMultiFactorFailureAttemptId(Guid.Empty));
    }

    [Fact]
    public void Default_struct_values_remain_empty_for_aggregate_defensive_checks()
    {
        Assert.Equal(Guid.Empty, default(MemberId).Value);
        Assert.Equal(Guid.Empty, default(MemberUsernameId).Value);
        Assert.Equal(Guid.Empty, default(MemberSessionId).Value);
        Assert.Equal(Guid.Empty, default(MemberTotpAuthenticatorId).Value);
        Assert.Equal(Guid.Empty, default(MemberTotpRecoveryCodeId).Value);
        Assert.Equal(Guid.Empty, default(MemberAuthenticationChallengeId).Value);
        Assert.Equal(Guid.Empty, default(MemberMultiFactorFailureAttemptId).Value);
    }

    [Fact]
    public void Multi_factor_failure_attempt_rejects_a_default_id()
    {
        Result<MemberMultiFactorFailureAttempt> result = MemberMultiFactorFailureAttempt.Create(
            default,
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            MemberMultiFactorFailureAttempt.ManagementPurpose,
            DateTimeOffset.UtcNow);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.MultiFactorFailureAttemptIdRequired, result.Error);
    }

    [Fact]
    public void Access_token_claims_normalize_and_validate_identity()
    {
        MemberId memberId = new(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        MemberSessionId sessionId = new(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"));
        SessionAuthenticationEvidence evidence = SessionAuthenticationEvidence.Password(DateTimeOffset.UtcNow);

        AccessTokenClaims claims = new(memberId, " tenant-a ", sessionId, evidence);

        Assert.Equal(memberId, claims.MemberId);
        Assert.Equal("tenant-a", claims.ScopeId);
        Assert.Equal(sessionId, claims.SessionId);
        Assert.Same(evidence, claims.AuthenticationEvidence);
        Assert.Throws<ArgumentException>(() => new AccessTokenClaims(default, "tenant-a", sessionId, evidence));
        Assert.Throws<ArgumentException>(() => new AccessTokenClaims(memberId, "tenant-a", default, evidence));
        Assert.Throws<ArgumentException>(() => new AccessTokenClaims(memberId, " ", sessionId, evidence));
        Assert.Throws<ArgumentException>(() => new AccessTokenClaims(
            memberId,
            new string('x', ScopeIds.MaxLength + 1),
            sessionId,
            evidence));
        Assert.Throws<ArgumentNullException>(() => new AccessTokenClaims(memberId, "tenant-a", sessionId, null!));
    }
}
