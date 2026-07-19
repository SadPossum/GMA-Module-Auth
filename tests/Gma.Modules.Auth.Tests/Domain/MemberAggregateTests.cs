namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Domain;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;
using Xunit;

[Trait("Category", "Unit")]
public sealed class MemberAggregateTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 14, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Create_rejects_invalid_username()
    {
        var result = CreateMember("not-an-email");
        var missing = CreateMember(null!);
        var overlong = CreateMember($"{new string('x', MemberUsername.ValueMaxLength)}@example.com");

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.UsernameNotValid, result.Error);
        Assert.True(missing.IsFailure);
        Assert.Equal(AuthDomainErrors.UsernameNotValid, missing.Error);
        Assert.True(overlong.IsFailure);
        Assert.Equal(AuthDomainErrors.UsernameNotValid, overlong.Error);
    }

    [Fact]
    public void Create_rejects_overlong_password_hash()
    {
        var result = CreateMember("member@example.com", passwordHash: new string('x', Member.PasswordHashMaxLength + 1));

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.PasswordNotValid, result.Error);
    }

    [Fact]
    public void Create_raises_registered_domain_event()
    {
        var result = CreateMember("member@example.com");

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value.DomainEvents);
    }

    [Fact]
    public void Create_normalizes_and_rejects_invalid_tenant_id()
    {
        var normalized = CreateMember("member@example.com", " tenant-a ");
        var missing = CreateMember("member@example.com", " ");
        var invalid = CreateMember("member@example.com", new string('x', ScopeIds.MaxLength + 1));

        Assert.True(normalized.IsSuccess);
        Assert.Equal("tenant-a", normalized.Value.ScopeId);
        Assert.True(missing.IsFailure);
        Assert.Equal(AuthDomainErrors.TenantRequired, missing.Error);
        Assert.True(invalid.IsFailure);
        Assert.Equal(AuthDomainErrors.TenantInvalid, invalid.Error);
    }

    [Fact]
    public void Create_rejects_empty_ids_and_event_id()
    {
        var emptyMemberId = CreateMember("member@example.com", memberId: default(MemberId));
        var emptyUsernameId = CreateMember("member@example.com", usernameId: default(MemberUsernameId));
        var emptyEventId = CreateMember("member@example.com", registeredEventId: Guid.Empty);

        Assert.True(emptyMemberId.IsFailure);
        Assert.Equal(AuthDomainErrors.MemberIdRequired, emptyMemberId.Error);
        Assert.True(emptyUsernameId.IsFailure);
        Assert.Equal(AuthDomainErrors.UsernameIdRequired, emptyUsernameId.Error);
        Assert.True(emptyEventId.IsFailure);
        Assert.Equal(AuthDomainErrors.DomainEventIdRequired, emptyEventId.Error);
    }

    [Fact]
    public void Has_active_username_uses_normalized_value()
    {
        var result = CreateMember("Member@Example.com");

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.HasActiveUsername("member@example.com"));
        Assert.False(result.Value.HasActiveUsername(null!));
    }

    [Fact]
    public void Add_username_validates_before_deactivating_current_username()
    {
        var member = CreateMember("member@example.com").Value;

        var result = member.AddUsername(
            new MemberUsernameId(Guid.NewGuid()),
            "not-an-email",
            MemberUsernameType.Email);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.UsernameNotValid, result.Error);
        MemberUsername username = Assert.Single(member.Usernames);
        Assert.True(username.IsActive);
        Assert.Equal("member@example.com", username.Value);
    }

    [Fact]
    public void Add_username_rejects_empty_id_before_deactivating_current_username()
    {
        var member = CreateMember("member@example.com").Value;

        var result = member.AddUsername(
            default,
            "other@example.com",
            MemberUsernameType.Email);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.UsernameIdRequired, result.Error);
        MemberUsername username = Assert.Single(member.Usernames);
        Assert.True(username.IsActive);
        Assert.Equal("member@example.com", username.Value);
    }

    [Fact]
    public void Add_username_rejects_reusing_historical_username()
    {
        var member = CreateMember("member@example.com").Value;
        var changed = member.AddUsername(
            new MemberUsernameId(Guid.NewGuid()),
            "other@example.com",
            MemberUsernameType.Email);

        var duplicate = member.AddUsername(
            new MemberUsernameId(Guid.NewGuid()),
            "MEMBER@example.com",
            MemberUsernameType.Email);

        Assert.True(changed.IsSuccess);
        Assert.True(duplicate.IsFailure);
        Assert.Equal(AuthDomainErrors.UsernameAlreadyExists, duplicate.Error);
        Assert.Equal(2, member.Usernames.Count);
        Assert.Contains(member.Usernames, username => username.Value == "member@example.com" && !username.IsActive);
        Assert.Contains(member.Usernames, username => username.Value == "other@example.com" && username.IsActive);
    }

    [Fact]
    public void Refresh_session_rotates_refresh_token_hash()
    {
        var member = CreateMember("member@example.com").Value;
        MemberSessionId sessionId = new(Guid.NewGuid());
        member.StartSession(sessionId, "refresh-hash-1", Now.AddDays(1), Now);

        var result = member.RefreshSession(
            sessionId,
            "refresh-hash-1",
            "refresh-hash-2",
            Now.AddDays(1),
            Now);

        Assert.True(result.IsSuccess);
        Assert.Equal("refresh-hash-2", result.Value.RefreshTokenHash);
    }

    [Fact]
    public void Start_session_rejects_invalid_refresh_token_hash()
    {
        var member = CreateMember("member@example.com").Value;

        var blank = member.StartSession(new MemberSessionId(Guid.NewGuid()), " ", Now.AddDays(1), Now);
        var overlong = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            new string('x', MemberSession.RefreshTokenHashMaxLength + 1),
            Now.AddDays(1),
            Now);

        Assert.True(blank.IsFailure);
        Assert.Equal(AuthDomainErrors.RefreshTokenHashNotValid, blank.Error);
        Assert.True(overlong.IsFailure);
        Assert.Equal(AuthDomainErrors.RefreshTokenHashNotValid, overlong.Error);
    }

    [Fact]
    public void Start_session_rejects_empty_session_id()
    {
        var member = CreateMember("member@example.com").Value;

        var result = member.StartSession(default, "refresh-hash-1", Now.AddDays(1), Now);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.SessionIdRequired, result.Error);
    }

    [Fact]
    public void Start_session_retires_only_the_oldest_unexpired_session_above_the_limit()
    {
        Member member = CreateMember("member@example.com").Value;
        MemberSession expired = member.StartSession(
            new MemberSessionId(Guid.Parse("00000000-0000-0000-0000-000000000100")),
            "expired-hash",
            Now.AddMinutes(-1),
            Now.AddHours(-2),
            maximumActiveSessions: int.MaxValue).Value;
        MemberSession oldest = member.StartSession(
            new MemberSessionId(Guid.Parse("00000000-0000-0000-0000-000000000020")),
            "oldest-hash",
            Now.AddDays(1),
            Now,
            maximumActiveSessions: 2).Value;
        MemberSession newer = member.StartSession(
            new MemberSessionId(Guid.Parse("00000000-0000-0000-0000-000000000030")),
            "newer-hash",
            Now.AddDays(1),
            Now,
            maximumActiveSessions: 2).Value;

        MemberSession newest = member.StartSession(
            new MemberSessionId(Guid.Parse("00000000-0000-0000-0000-000000000010")),
            "newest-hash",
            Now.AddDays(1),
            Now,
            maximumActiveSessions: 2).Value;

        Assert.True(expired.IsActive);
        Assert.False(oldest.IsActive);
        Assert.True(newer.IsActive);
        Assert.True(newest.IsActive);
    }

    [Fact]
    public void Refresh_session_rejects_invalid_new_refresh_token_hash()
    {
        var member = CreateMember("member@example.com").Value;
        MemberSessionId sessionId = new(Guid.NewGuid());
        member.StartSession(sessionId, "refresh-hash-1", Now.AddDays(1), Now);

        var result = member.RefreshSession(
            sessionId,
            "refresh-hash-1",
            new string('x', MemberSession.RefreshTokenHashMaxLength + 1),
            Now.AddDays(1),
            Now);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.RefreshTokenHashNotValid, result.Error);
    }

    [Fact]
    public void Disable_revokes_active_sessions_and_blocks_new_sessions()
    {
        var member = CreateMember("member@example.com").Value;
        member.StartSession(new MemberSessionId(Guid.NewGuid()), "refresh-hash-1", Now.AddDays(1), Now);

        var disableResult = member.Disable("support request", Guid.NewGuid(), Now);
        var startResult = member.StartSession(new MemberSessionId(Guid.NewGuid()), "refresh-hash-2", Now.AddDays(1), Now);

        Assert.True(disableResult.IsSuccess);
        Assert.All(member.Sessions, session => Assert.False(session.IsActive));
        Assert.True(startResult.IsFailure);
        Assert.Equal(AuthDomainErrors.MemberDisabled, startResult.Error);
    }

    [Fact]
    public void Sign_out_session_only_revokes_the_selected_session()
    {
        Member member = CreateMember("member@example.com").Value;
        MemberSessionId selectedSessionId = new(Guid.NewGuid());
        MemberSessionId otherSessionId = new(Guid.NewGuid());
        member.StartSession(selectedSessionId, "refresh-hash-1", Now.AddDays(1), Now);
        member.StartSession(otherSessionId, "refresh-hash-2", Now.AddDays(1), Now);

        Result result = member.SignOutSession(selectedSessionId, Now.AddMinutes(1));

        Assert.True(result.IsSuccess);
        Assert.False(member.Sessions.Single(session => session.Id == selectedSessionId).IsActive);
        Assert.True(member.Sessions.Single(session => session.Id == otherSessionId).IsActive);
    }

    [Fact]
    public void Disable_requires_reason()
    {
        var member = CreateMember("member@example.com").Value;

        var blankResult = member.Disable(" ", Guid.NewGuid(), Now);
        var nullResult = member.Disable(null!, Guid.NewGuid(), Now);

        Assert.True(blankResult.IsFailure);
        Assert.Equal(AuthDomainErrors.DisableReasonRequired, blankResult.Error);
        Assert.True(nullResult.IsFailure);
        Assert.Equal(AuthDomainErrors.DisableReasonRequired, nullResult.Error);
    }

    [Fact]
    public void Disable_enable_and_revoke_sessions_reject_empty_event_id()
    {
        var member = CreateMember("member@example.com").Value;
        member.StartSession(new MemberSessionId(Guid.NewGuid()), "refresh-hash-1", Now.AddDays(1), Now);

        Result disableResult = member.Disable("support request", Guid.Empty, Now);
        Result<int> revokeResult = member.RevokeSessions(Guid.Empty, Now);

        Assert.True(disableResult.IsFailure);
        Assert.Equal(AuthDomainErrors.DomainEventIdRequired, disableResult.Error);
        Assert.Equal(MemberStatus.Active, member.Status);
        Assert.True(revokeResult.IsFailure);
        Assert.Equal(AuthDomainErrors.DomainEventIdRequired, revokeResult.Error);
        Assert.All(member.Sessions, session => Assert.True(session.IsActive));

        Result validDisable = member.Disable("support request", Guid.NewGuid(), Now);
        Result enableResult = member.Enable(Guid.Empty, Now.AddMinutes(1));

        Assert.True(validDisable.IsSuccess);
        Assert.True(enableResult.IsFailure);
        Assert.Equal(AuthDomainErrors.DomainEventIdRequired, enableResult.Error);
        Assert.Equal(MemberStatus.Disabled, member.Status);
    }

    [Fact]
    public void Disable_rejects_overlong_reason()
    {
        var member = CreateMember("member@example.com").Value;
        string reason = new('x', Member.DisabledReasonMaxLength + 1);

        var result = member.Disable(reason, Guid.NewGuid(), Now);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.DisableReasonTooLong, result.Error);
    }

    [Fact]
    public void Disable_trims_reason_for_state_and_event()
    {
        var member = CreateMember("member@example.com").Value;

        var result = member.Disable(" support request ", Guid.NewGuid(), Now);

        Assert.True(result.IsSuccess);
        Assert.Equal("support request", member.DisabledReason);
        Assert.Equal(
            "support request",
            member.DomainEvents.OfType<MemberDisabledDomainEvent>().Single().Reason);
    }

    [Fact]
    public void Enable_reactivates_disabled_member()
    {
        var member = CreateMember("member@example.com").Value;
        member.Disable("support request", Guid.NewGuid(), Now);

        var result = member.Enable(Guid.NewGuid(), Now.AddMinutes(1));

        Assert.True(result.IsSuccess);
        Assert.Equal(MemberStatus.Active, member.Status);
        Assert.Null(member.DisabledReason);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(999)]
    public void Authentication_and_security_mutations_reject_unknown_member_status(int statusValue)
    {
        var member = CreateMember("member@example.com").Value;
        MemberSessionId sessionId = new(Guid.NewGuid());
        Result<MemberSession> session = member.StartSession(sessionId, "refresh-hash-1", Now.AddDays(1), Now);
        Assert.True(session.IsSuccess);
        member.ClearDomainEvents();
        SetStatus(member, (MemberStatus)statusValue);

        Result<MemberSession> startSession = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "refresh-hash-2",
            Now.AddDays(1),
            Now);
        Result<MemberSession> refreshSession = member.RefreshSession(
            sessionId,
            "refresh-hash-1",
            "refresh-hash-2",
            Now.AddDays(1),
            Now);
        Result disable = member.Disable("support request", Guid.NewGuid(), Now);
        Result enable = member.Enable(Guid.NewGuid(), Now);
        Result resetPassword = member.ResetPassword("new-hash");

        Assert.Equal(AuthDomainErrors.MemberStatusUnknown, startSession.Error);
        Assert.Equal(AuthDomainErrors.MemberStatusUnknown, refreshSession.Error);
        Assert.Equal(AuthDomainErrors.MemberStatusUnknown, disable.Error);
        Assert.Equal(AuthDomainErrors.MemberStatusUnknown, enable.Error);
        Assert.Equal(AuthDomainErrors.MemberStatusUnknown, resetPassword.Error);
        Assert.Equal((MemberStatus)statusValue, member.Status);
        Assert.Empty(member.DomainEvents);
    }

    [Fact]
    public void Reset_password_rejects_overlong_hash()
    {
        var member = CreateMember("member@example.com").Value;

        var result = member.ResetPassword(new string('x', Member.PasswordHashMaxLength + 1));

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.PasswordNotValid, result.Error);
    }

    [Fact]
    public void Reusing_previous_refresh_token_revokes_the_member_token_family()
    {
        Member member = CreateMember("member@example.com").Value;
        MemberSessionId firstSessionId = new(Guid.NewGuid());
        MemberSessionId secondSessionId = new(Guid.NewGuid());
        member.StartSession(firstSessionId, "refresh-hash-1", Now.AddDays(1), Now);
        member.StartSession(secondSessionId, "refresh-hash-other", Now.AddDays(1), Now);
        member.RefreshSession(
            firstSessionId,
            "refresh-hash-1",
            "refresh-hash-2",
            Now.AddDays(1),
            Now);

        Result<MemberSession> reuse = member.RefreshSession(
            firstSessionId,
            "refresh-hash-1",
            "refresh-hash-3",
            Now.AddDays(1),
            Now.AddMinutes(1));

        Assert.True(reuse.IsFailure);
        Assert.Equal(AuthDomainErrors.RefreshTokenReused, reuse.Error);
        Assert.All(member.Sessions, session => Assert.False(session.IsActive));
    }

    [Fact]
    public void External_registration_creates_verified_email_and_passwordless_identity()
    {
        Result<Member> result = Member.CreateExternal(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "member@example.com",
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "Google",
            "https://accounts.google.com",
            "provider-subject",
            Guid.NewGuid(),
            Now);

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.HasPassword);
        Assert.True(Assert.Single(result.Value.Usernames).IsVerified);
        Assert.Equal("google", Assert.Single(result.Value.ExternalIdentities).ProviderCode);
    }

    [Fact]
    public void External_registration_rejects_control_characters_in_identity_components()
    {
        Result<Member> result = Member.CreateExternal(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "member@example.com",
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            "subject\n2",
            Guid.NewGuid(),
            Now);

        Assert.True(result.IsFailure);
        Assert.Equal(AuthDomainErrors.ExternalIdentityNotValid, result.Error);
    }

    [Fact]
    public void Removing_last_authentication_method_is_rejected()
    {
        Member passwordOnly = CreateMember("password@example.com").Value;
        Result removePassword = passwordOnly.RemovePassword();

        Member externalOnly = Member.CreateExternal(
            new MemberId(Guid.NewGuid()),
            "tenant-a",
            "external@example.com",
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            "subject",
            Guid.NewGuid(),
            Now).Value;
        Result unlink = externalOnly.UnlinkExternalIdentity(Assert.Single(externalOnly.ExternalIdentities).Id);

        Assert.Equal(AuthDomainErrors.AuthenticationMethodRequired, removePassword.Error);
        Assert.Equal(AuthDomainErrors.AuthenticationMethodRequired, unlink.Error);
    }

    [Fact]
    public void Multiple_external_identities_can_be_linked_and_unlinked_without_lockout()
    {
        Member member = CreateMember("member@example.com").Value;
        Result<MemberExternalIdentity> google = member.LinkExternalIdentity(
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            "google-subject",
            Now);
        Result<MemberExternalIdentity> microsoft = member.LinkExternalIdentity(
            new MemberExternalIdentityId(Guid.NewGuid()),
            "microsoft",
            "https://login.microsoftonline.com/common/v2.0",
            "microsoft-subject",
            Now);
        Result unlink = member.UnlinkExternalIdentity(google.Value.Id);

        Assert.True(google.IsSuccess);
        Assert.True(microsoft.IsSuccess);
        Assert.True(unlink.IsSuccess);
        Assert.Equal("microsoft", Assert.Single(member.ExternalIdentities).ProviderCode);
    }

    [Fact]
    public void Session_records_the_authentication_method()
    {
        Member member = CreateMember("member@example.com").Value;

        Result<MemberSession> result = member.StartSession(
            new MemberSessionId(Guid.NewGuid()),
            "refresh-hash",
            Now.AddDays(1),
            Now,
            MemberAuthenticationMethods.External("Google"));

        Assert.True(result.IsSuccess);
        Assert.Equal("external:google", result.Value.AuthenticationMethod);
    }

    [Fact]
    public void Email_verification_is_single_use_and_expires()
    {
        Member member = CreateMember("member@example.com").Value;
        MemberUsername username = Assert.Single(member.Usernames);

        Result requested = member.RequestEmailVerification(
            username.Id,
            "verification-hash",
            "verification-code",
            Guid.NewGuid(),
            Now.AddMinutes(30),
            Now);
        Result invalid = member.ConfirmEmailVerification(
            username.Id,
            "wrong-hash",
            Guid.NewGuid(),
            Now.AddMinutes(1));
        Result confirmed = member.ConfirmEmailVerification(
            username.Id,
            "verification-hash",
            Guid.NewGuid(),
            Now.AddMinutes(1));
        Result repeated = member.ConfirmEmailVerification(
            username.Id,
            "verification-hash",
            Guid.NewGuid(),
            Now.AddMinutes(2));

        Assert.True(requested.IsSuccess);
        Assert.Equal(AuthDomainErrors.EmailVerificationTokenNotValid, invalid.Error);
        Assert.True(confirmed.IsSuccess);
        Assert.True(repeated.IsSuccess);
        Assert.True(username.IsVerified);
        Assert.Null(username.VerificationTokenHash);
    }

    [Fact]
    public void Authentication_method_changes_raise_an_auditable_domain_event()
    {
        Member member = CreateMember("member@example.com").Value;
        member.ClearDomainEvents();

        Result result = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.External("Google"),
            MemberAuthenticationMethodChange.Added,
            Guid.NewGuid(),
            Now);

        Assert.True(result.IsSuccess);
        MemberAuthenticationMethodChangedDomainEvent domainEvent = Assert.Single(
            member.DomainEvents.OfType<MemberAuthenticationMethodChangedDomainEvent>());
        Assert.Equal("external:google", domainEvent.AuthenticationMethod);
        Assert.Equal(MemberAuthenticationMethodChange.Added, domainEvent.Change);
    }

    private static Result<Member> CreateMember(
        string username,
        string scopeId = "tenant-a",
        string passwordHash = "hash",
        MemberId? memberId = null,
        MemberUsernameId? usernameId = null,
        Guid? registeredEventId = null) =>
        Member.Create(
            memberId ?? new MemberId(Guid.NewGuid()),
            scopeId,
            username,
            MemberUsernameType.Email,
            passwordHash,
            usernameId ?? new MemberUsernameId(Guid.NewGuid()),
            registeredEventId ?? Guid.NewGuid(),
            Now);

    private static void SetStatus(Member member, MemberStatus status) =>
        typeof(Member)
            .GetProperty(nameof(Member.Status))!
            .GetSetMethod(nonPublic: true)!
            .Invoke(member, [status]);
}
