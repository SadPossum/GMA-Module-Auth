namespace Gma.Modules.Auth.Tests;

using System.Text.Json;
using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthIntegrationEventContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly Guid EventId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static readonly Guid MemberId = Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff");
    private static readonly DateTimeOffset OccurredAtUtc = new(2026, 7, 2, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Contract_limits_match_domain_limits()
    {
        Assert.Equal(MemberUsername.ValueMaxLength, AuthContractLimits.UsernameMaxLength);
        Assert.Equal(Member.DisabledReasonMaxLength, AuthContractLimits.DisableReasonMaxLength);
    }

    [Fact]
    public void Auth_subjects_support_default_and_configured_application_namespaces()
    {
        Assert.Equal("gma.auth.member-registered.v1", AuthIntegrationSubjects.MemberRegistered);
        Assert.Equal("acme-orders.auth.member-registered.v1", AuthIntegrationSubjects.CreateMemberRegistered("acme-orders"));
        Assert.Equal("acme-orders.auth.member-disabled.v1", AuthIntegrationSubjects.CreateMemberDisabled("acme-orders"));
        Assert.Equal("acme-orders.auth.member-enabled.v1", AuthIntegrationSubjects.CreateMemberEnabled("acme-orders"));
        Assert.Equal(
            "acme-orders.auth.member-sessions-revoked.v1",
            AuthIntegrationSubjects.CreateMemberSessionsRevoked("acme-orders"));
        Assert.Equal(
            "acme-orders.auth.member-authentication-method-changed.v1",
            AuthIntegrationSubjects.CreateMemberAuthenticationMethodChanged("acme-orders"));
        Assert.Equal(
            "acme-orders.auth.member-password-recovery-requested.v1",
            AuthIntegrationSubjects.CreateMemberPasswordRecoveryRequested("acme-orders"));
    }

    [Fact]
    public void Member_registered_event_normalizes_metadata_and_username()
    {
        MemberRegisteredIntegrationEvent integrationEvent = new(
            EventId,
            " tenant-a ",
            OccurredAtUtc,
            MemberId,
            " user@example.com ");

        Assert.Equal(EventId, integrationEvent.EventId);
        Assert.Equal("tenant-a", integrationEvent.ScopeId);
        Assert.Equal(OccurredAtUtc, integrationEvent.OccurredAtUtc);
        Assert.Equal(MemberId, integrationEvent.MemberId);
        Assert.Equal("user@example.com", integrationEvent.Username);
    }

    [Fact]
    public void Member_registered_event_round_trips_through_web_json()
    {
        MemberRegisteredIntegrationEvent integrationEvent = new(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            "user@example.com");

        string json = JsonSerializer.Serialize(integrationEvent, JsonOptions);
        MemberRegisteredIntegrationEvent? deserialized = JsonSerializer.Deserialize<MemberRegisteredIntegrationEvent>(
            json,
            JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal(integrationEvent, deserialized);
    }

    [Fact]
    public void Auth_events_reject_invalid_metadata_and_payload()
    {
        Assert.Throws<ArgumentException>(() => new MemberRegisteredIntegrationEvent(
            Guid.Empty,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            "user@example.com"));
        Assert.Throws<ArgumentException>(() => new MemberRegisteredIntegrationEvent(
            EventId,
            " ",
            OccurredAtUtc,
            MemberId,
            "user@example.com"));
        Assert.Throws<ArgumentException>(() => new MemberRegisteredIntegrationEvent(
            EventId,
            "tenant-a",
            default,
            MemberId,
            "user@example.com"));
        Assert.Throws<ArgumentException>(() => new MemberRegisteredIntegrationEvent(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            Guid.Empty,
            "user@example.com"));
        Assert.Throws<ArgumentException>(() => new MemberRegisteredIntegrationEvent(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            " "));
    }

    [Fact]
    public void Member_disabled_event_normalizes_reason()
    {
        MemberDisabledIntegrationEvent integrationEvent = new(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            " support request ");

        Assert.Equal("support request", integrationEvent.Reason);
    }

    [Fact]
    public void Member_sessions_revoked_event_allows_zero_count_and_rejects_negative_count()
    {
        MemberSessionsRevokedIntegrationEvent integrationEvent = new(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            0);

        Assert.Equal(0, integrationEvent.RevokedSessionCount);
        Assert.Throws<ArgumentOutOfRangeException>(() => new MemberSessionsRevokedIntegrationEvent(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            -1));
    }

    [Fact]
    public void Authentication_method_change_accepts_known_changes_and_rejects_unknown_values()
    {
        MemberAuthenticationMethodChangedIntegrationEvent integrationEvent = new(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            "external:google",
            AuthenticationMethodChange.Added);

        Assert.Equal("external:google", integrationEvent.AuthenticationMethod);
        Assert.Equal(AuthenticationMethodChange.Added, integrationEvent.Change);
        Assert.Throws<ArgumentOutOfRangeException>(() => new MemberAuthenticationMethodChangedIntegrationEvent(
            EventId,
            "tenant-a",
            OccurredAtUtc,
            MemberId,
            "external:google",
            AuthenticationMethodChange.Unknown));
    }

    [Fact]
    public void Password_recovery_requested_event_keeps_the_challenge_and_exact_destination()
    {
        Guid challengeId = Guid.NewGuid();
        MemberPasswordRecoveryRequestedIntegrationEvent integrationEvent = new(
            EventId,
            " tenant-a ",
            OccurredAtUtc,
            challengeId,
            MemberId,
            " owner@example.com ",
            " recovery-code ",
            OccurredAtUtc.AddMinutes(30));

        Assert.Equal("tenant-a", integrationEvent.ScopeId);
        Assert.Equal(challengeId, integrationEvent.ChallengeId);
        Assert.Equal("owner@example.com", integrationEvent.Email);
        Assert.Equal("recovery-code", integrationEvent.RecoveryCode);
        Assert.Contains(
            AuthModuleMetadata.Descriptor.GetPublishedEvents(),
            published => published.EventType == MemberPasswordRecoveryRequestedIntegrationEvent.EventType);
    }
}
