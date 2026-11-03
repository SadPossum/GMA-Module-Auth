namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Application.Validation;
using Gma.Modules.Auth.Contracts;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthInputValidationTests
{
    private static readonly Guid MemberId = Guid.NewGuid();
    private static readonly Guid SessionId = Guid.NewGuid();

    [Fact]
    public void Registration_validators_reject_oversized_usernames()
    {
        string username = Oversized(AuthContractLimits.UsernameMaxLength);

        AssertTooLong(new RegisterMemberCommandValidator().Validate(
            new RegisterMemberCommand(username, UsernameType.Email, ValidPassword())));
        AssertTooLong(new AdminCreateMemberCommandValidator().Validate(
            new AdminCreateMemberCommand(username, UsernameType.Email, ValidPassword())));
    }

    [Fact]
    public void Login_validator_rejects_oversized_credentials()
    {
        var validator = new LoginMemberCommandValidator();

        AssertTooLong(validator.Validate(new LoginMemberCommand(
            Oversized(AuthContractLimits.UsernameMaxLength),
            ValidPassword())));
        AssertTooLong(validator.Validate(new LoginMemberCommand(
            "member@example.com",
            Oversized(AuthPasswordPolicy.MaximumLength))));
    }

    [Fact]
    public void Session_validators_reject_oversized_tokens()
    {
        AssertTooLong(new RefreshMemberSessionCommandValidator().Validate(
            new RefreshMemberSessionCommand(
                Oversized(AuthContractLimits.AccessTokenMaxLength),
                ValidOpaqueToken())));
        AssertTooLong(new RefreshMemberSessionCommandValidator().Validate(
            new RefreshMemberSessionCommand("access-token", Oversized(AuthContractLimits.OpaqueTokenMaxLength))));
        AssertTooLong(new SignOutCommandValidator().Validate(
            new SignOutCommand(MemberId, Oversized(AuthContractLimits.OpaqueTokenMaxLength))));
    }

    [Fact]
    public void Password_proof_validators_reject_oversized_material()
    {
        string password = Oversized(AuthPasswordPolicy.MaximumLength);

        AssertTooLong(new StepUpWithPasswordCommandValidator().Validate(
            new StepUpWithPasswordCommand(MemberId, SessionId, password, ValidOpaqueToken())));
        AssertTooLong(new SetMemberPasswordCommandValidator().Validate(
            new SetMemberPasswordCommand(MemberId, SessionId, ValidPassword(), password, ValidOpaqueToken())));
        AssertTooLong(new RemoveMemberPasswordCommandValidator().Validate(
            new RemoveMemberPasswordCommand(MemberId, SessionId, password, ValidOpaqueToken())));
        AssertTooLong(new UnlinkExternalIdentityCommandValidator().Validate(
            new UnlinkExternalIdentityCommand(
                MemberId,
                SessionId,
                Guid.NewGuid(),
                password,
                ValidOpaqueToken())));

        string token = Oversized(AuthContractLimits.OpaqueTokenMaxLength);
        AssertTooLong(new SetMemberPasswordCommandValidator().Validate(
            new SetMemberPasswordCommand(MemberId, SessionId, ValidPassword(), null, token)));
        AssertTooLong(new RemoveMemberPasswordCommandValidator().Validate(
            new RemoveMemberPasswordCommand(MemberId, SessionId, ValidPassword(), token)));
        AssertTooLong(new UnlinkExternalIdentityCommandValidator().Validate(
            new UnlinkExternalIdentityCommand(MemberId, SessionId, Guid.NewGuid(), null, token)));
    }

    [Fact]
    public void Multi_factor_validators_reject_oversized_proofs()
    {
        string code = Oversized(AuthContractLimits.AuthenticationCodeMaxLength);
        string token = Oversized(AuthContractLimits.OpaqueTokenMaxLength);

        AssertTooLong(new ActivateTotpCommandValidator().Validate(
            new ActivateTotpCommand(MemberId, SessionId, code, ValidOpaqueToken())));
        AssertTooLong(new CompleteMultiFactorChallengeCommandValidator().Validate(
            new CompleteMultiFactorChallengeCommand(token, MultiFactorCodeType.Totp, "123456")));
        AssertTooLong(new CompleteMultiFactorChallengeCommandValidator().Validate(
            new CompleteMultiFactorChallengeCommand("challenge-token", MultiFactorCodeType.Totp, code)));
        AssertTooLong(new RegenerateMultiFactorRecoveryCodesCommandValidator().Validate(
            new RegenerateMultiFactorRecoveryCodesCommand(
                MemberId,
                SessionId,
                MultiFactorCodeType.Totp,
                code,
                ValidOpaqueToken())));
        AssertTooLong(new DisableTotpCommandValidator().Validate(
            new DisableTotpCommand(MemberId, SessionId, MultiFactorCodeType.Totp, "123456", token)));
        AssertTooLong(new StepUpWithMultiFactorCommandValidator().Validate(
            new StepUpWithMultiFactorCommand(
                MemberId,
                SessionId,
                ValidPassword(),
                MultiFactorCodeType.Totp,
                code,
                ValidOpaqueToken())));
        AssertTooLong(new StepUpWithMultiFactorCommandValidator().Validate(
            new StepUpWithMultiFactorCommand(
                MemberId,
                SessionId,
                ValidPassword(),
                MultiFactorCodeType.Totp,
                "123456",
                token)));
        AssertTooLong(new StepUpWithMultiFactorCommandValidator().Validate(
            new StepUpWithMultiFactorCommand(
                MemberId,
                SessionId,
                Oversized(AuthPasswordPolicy.MaximumLength),
                MultiFactorCodeType.Totp,
                "123456",
                ValidOpaqueToken())));
    }

    [Fact]
    public void Multi_factor_step_up_validator_rejects_missing_identity_and_unknown_code_type()
    {
        string[] errors = [.. new StepUpWithMultiFactorCommandValidator().Validate(
            new StepUpWithMultiFactorCommand(
                Guid.Empty,
                Guid.Empty,
                ValidPassword(),
                MultiFactorCodeType.Unknown,
                "123456",
                ValidOpaqueToken()))];

        Assert.Contains(errors, error => error.Contains("Member id", StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains("Session id", StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains("code type", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Administrative_validator_rejects_oversized_disable_reason()
    {
        AssertTooLong(new DisableMemberCommandValidator().Validate(
            new DisableMemberCommand(MemberId, Oversized(AuthContractLimits.DisableReasonMaxLength))));
    }

    [Fact]
    public void External_handoff_validator_enforces_intent_and_target_shape()
    {
        ValidatedExternalIdentity identity = new(
            "google",
            "https://accounts.google.com",
            "provider-subject",
            "member@example.com",
            emailVerified: true);
        var validator = new CreateExternalAuthenticationHandoffCommandValidator();

        string[] invalidIntent = [.. validator.Validate(new CreateExternalAuthenticationHandoffCommand(
            identity,
            (ExternalAuthenticationIntent)999,
            "/signed-in",
            null,
            null))];
        string[] targetedSignIn = [.. validator.Validate(new CreateExternalAuthenticationHandoffCommand(
            identity,
            ExternalAuthenticationIntent.SignIn,
            "/signed-in",
            MemberId,
            SessionId))];

        Assert.Contains(invalidIntent, error => error.Contains("intent", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(targetedSignIn, error => error.Contains("cannot target", StringComparison.OrdinalIgnoreCase));
    }

    private static string Oversized(int maximumLength) => new('x', maximumLength + 1);

    private static string ValidPassword() => new('p', AuthPasswordPolicy.MinimumLength);

    private static string ValidOpaqueToken() => "opaque-token";

    private static void AssertTooLong(IEnumerable<string> errors) =>
        Assert.Contains(
            errors,
            error => error.Contains("too long", StringComparison.OrdinalIgnoreCase) ||
                     error.Contains("no more than", StringComparison.OrdinalIgnoreCase));
}
