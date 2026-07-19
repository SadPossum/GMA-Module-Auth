namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;
using Xunit;

[Trait("Category", "Unit")]
public sealed class MemberTotpAuthenticatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Enrollment_activation_enforces_one_time_totp_steps()
    {
        MemberTotpAuthenticator authenticator = CreatePending();

        var activated = authenticator.Activate(42, CreateRecoveryCodes("initial"), Now.AddMinutes(1));
        var replay = authenticator.AcceptTotp(42);
        var older = authenticator.AcceptTotp(41);
        var next = authenticator.AcceptTotp(43);

        Assert.True(activated.IsSuccess);
        Assert.True(authenticator.IsActive);
        Assert.Equal(10, authenticator.UnusedRecoveryCodeCount);
        Assert.Equal(AuthDomainErrors.TotpCodeInvalid, replay.Error);
        Assert.Equal(AuthDomainErrors.TotpCodeInvalid, older.Error);
        Assert.True(next.IsSuccess);
        Assert.Equal(43, authenticator.LastAcceptedTimeStep);
    }

    [Fact]
    public void Recovery_codes_are_one_time_and_regeneration_revokes_old_codes()
    {
        MemberTotpAuthenticator authenticator = CreatePending();
        Assert.True(authenticator.Activate(42, CreateRecoveryCodes("initial"), Now.AddMinutes(1)).IsSuccess);

        var consumed = authenticator.ConsumeRecoveryCode(["initial-0"], Now.AddMinutes(2));
        var replay = authenticator.ConsumeRecoveryCode(["initial-0"], Now.AddMinutes(3));
        var regenerated = authenticator.RegenerateRecoveryCodes(
            CreateRecoveryCodes("replacement"),
            Now.AddMinutes(4));
        var oldCode = authenticator.ConsumeRecoveryCode(["initial-1"], Now.AddMinutes(5));
        var newCode = authenticator.ConsumeRecoveryCode(["replacement-1"], Now.AddMinutes(5));

        Assert.True(consumed.IsSuccess);
        Assert.Equal(AuthDomainErrors.TotpCodeInvalid, replay.Error);
        Assert.True(regenerated.IsSuccess);
        Assert.Equal(AuthDomainErrors.TotpCodeInvalid, oldCode.Error);
        Assert.True(newCode.IsSuccess);
        Assert.Equal(9, authenticator.UnusedRecoveryCodeCount);
    }

    [Fact]
    public void Active_authenticator_cannot_restart_and_disable_clears_secret_and_codes()
    {
        MemberTotpAuthenticator authenticator = CreatePending();
        Assert.True(authenticator.Activate(42, CreateRecoveryCodes("initial"), Now.AddMinutes(1)).IsSuccess);

        var restart = authenticator.RestartEnrollment("new-protected-secret", Now.AddMinutes(10), Now.AddMinutes(2));
        var disabled = authenticator.Disable(Now.AddMinutes(3));

        Assert.Equal(AuthDomainErrors.TotpAuthenticatorAlreadyActive, restart.Error);
        Assert.True(disabled.IsSuccess);
        Assert.False(authenticator.IsActive);
        Assert.Null(authenticator.ProtectedSecret);
        Assert.Equal(0, authenticator.UnusedRecoveryCodeCount);
    }

    [Fact]
    public void Expired_or_invalid_enrollment_cannot_activate()
    {
        MemberTotpAuthenticator authenticator = CreatePending();

        var expired = authenticator.Activate(42, CreateRecoveryCodes("initial"), Now.AddMinutes(6));
        var emptyCodes = authenticator.Activate(42, [], Now.AddMinutes(1));

        Assert.Equal(AuthDomainErrors.TotpEnrollmentInvalid, expired.Error);
        Assert.Equal(AuthDomainErrors.TotpRecoveryCodesInvalid, emptyCodes.Error);
    }

    [Fact]
    public void Administrative_reset_clears_active_state_and_records_actor_and_reason()
    {
        MemberTotpAuthenticator authenticator = CreatePending();
        Assert.True(authenticator.Activate(42, CreateRecoveryCodes("initial"), Now.AddMinutes(1)).IsSuccess);
        Guid eventId = Guid.NewGuid();

        var reset = authenticator.ResetByAdministrator(
            " verified account recovery ",
            "support-admin",
            eventId,
            Now.AddMinutes(2));

        Assert.True(reset.IsSuccess);
        Assert.False(authenticator.IsActive);
        Assert.Null(authenticator.ProtectedSecret);
        Assert.Equal(0, authenticator.UnusedRecoveryCodeCount);
        MemberMultiFactorAuthenticationResetDomainEvent domainEvent = Assert.IsType<MemberMultiFactorAuthenticationResetDomainEvent>(
            Assert.Single(authenticator.DomainEvents));
        Assert.Equal(eventId, domainEvent.EventId);
        Assert.Equal("support-admin", domainEvent.ActorId);
        Assert.Equal("verified account recovery", domainEvent.Reason);
    }

    [Fact]
    public void Administrative_reset_can_cancel_pending_enrollment_but_rejects_disabled_state()
    {
        MemberTotpAuthenticator authenticator = CreatePending();

        Assert.True(authenticator.ResetByAdministrator(
            "cancel enrollment",
            "support-admin",
            Guid.NewGuid(),
            Now.AddMinutes(1)).IsSuccess);

        var repeated = authenticator.ResetByAdministrator(
            "repeat",
            "support-admin",
            Guid.NewGuid(),
            Now.AddMinutes(2));

        Assert.Equal(AuthDomainErrors.TotpAuthenticatorNotActive, repeated.Error);
    }

    private static MemberTotpAuthenticator CreatePending() =>
        MemberTotpAuthenticator.BeginEnrollment(
            new MemberTotpAuthenticatorId(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")),
            new MemberId(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff")),
            "tenant-a",
            "protected-secret",
            Now.AddMinutes(5),
            Now).Value;

    private static TotpRecoveryCodeRegistration[] CreateRecoveryCodes(string prefix) =>
        Enumerable.Range(0, 10)
            .Select(index => new TotpRecoveryCodeRegistration(
                new MemberTotpRecoveryCodeId(Guid.Parse($"00000000-0000-0000-0000-{index + 1:000000000000}")),
                $"{prefix}-{index}"))
            .ToArray();
}
