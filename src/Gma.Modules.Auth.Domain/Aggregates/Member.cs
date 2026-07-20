namespace Gma.Modules.Auth.Domain.Aggregates;

using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed partial class Member : ScopedAggregateRoot<MemberId>
{
    public const int PasswordHashMaxLength = 512;
    public const int DisabledReasonMaxLength = 512;

    private readonly List<MemberSession> sessions = [];
    private readonly List<MemberUsername> usernames = [];
    private readonly List<MemberExternalIdentity> externalIdentities = [];

    private Member() { }

    private Member(MemberId id, string scopeId, string? passwordHash)
        : base(id, scopeId)
    {
        this.PasswordHash = passwordHash;
        this.Status = MemberStatus.Active;
    }

    public string? PasswordHash { get; private set; }
    public bool HasPassword => this.PasswordHash is not null;
    public Guid ConcurrencyStamp { get; private set; }
    public MemberStatus Status { get; private set; } = MemberStatus.Active;
    public DateTimeOffset RegisteredAtUtc { get; private set; }
    public DateTimeOffset? DisabledAtUtc { get; private set; }
    public string? DisabledReason { get; private set; }
    public IReadOnlyCollection<MemberUsername> Usernames => this.usernames;
    public IReadOnlyCollection<MemberSession> Sessions => this.sessions;
    public IReadOnlyCollection<MemberExternalIdentity> ExternalIdentities => this.externalIdentities;

    public static Result<Member> Create(
        MemberId id,
        string scopeId,
        string username,
        MemberUsernameType usernameType,
        string passwordHash,
        MemberUsernameId usernameId,
        Guid registeredEventId,
        DateTimeOffset registeredAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.MemberIdRequired);
        }

        if (registeredEventId == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.DomainEventIdRequired);
        }

        if (string.IsNullOrWhiteSpace(scopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantRequired);
        }

        if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantInvalid);
        }

        if (string.IsNullOrWhiteSpace(passwordHash) || passwordHash.Length > PasswordHashMaxLength)
        {
            return Result.Failure<Member>(AuthDomainErrors.PasswordNotValid);
        }

        Member member = new(id, normalizedScopeId, passwordHash)
        {
            RegisteredAtUtc = registeredAtUtc,
            ConcurrencyStamp = Guid.CreateVersion7()
        };
        Result<MemberUsername> usernameResult = member.AddUsername(usernameId, username, usernameType);

        if (usernameResult.IsFailure)
        {
            return Result.Failure<Member>(usernameResult.Error);
        }

        member.RaiseDomainEvent(new MemberRegisteredDomainEvent(
            registeredEventId,
            registeredAtUtc,
            member.Id,
            member.ScopeId,
            usernameResult.Value.Value));

        return Result.Success(member);
    }

    public static Result<Member> CreateExternal(
        MemberId id,
        string scopeId,
        string verifiedEmail,
        MemberUsernameId usernameId,
        MemberExternalIdentityId externalIdentityId,
        string provider,
        string issuer,
        string subject,
        Guid registeredEventId,
        DateTimeOffset registeredAtUtc)
    {
        if (registeredEventId == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.DomainEventIdRequired);
        }

        Result<Member> memberResult = CreateCore(id, scopeId, null, registeredAtUtc);
        if (memberResult.IsFailure)
        {
            return memberResult;
        }

        Member member = memberResult.Value;
        Result<MemberUsername> usernameResult = member.AddUsername(
            usernameId,
            verifiedEmail,
            MemberUsernameType.Email,
            registeredAtUtc);
        if (usernameResult.IsFailure)
        {
            return Result.Failure<Member>(usernameResult.Error);
        }

        Result<MemberExternalIdentity> identityResult = member.LinkExternalIdentity(
            externalIdentityId,
            provider,
            issuer,
            subject,
            registeredAtUtc);
        if (identityResult.IsFailure)
        {
            return Result.Failure<Member>(identityResult.Error);
        }

        member.RaiseDomainEvent(new MemberRegisteredDomainEvent(
            registeredEventId,
            registeredAtUtc,
            member.Id,
            member.ScopeId,
            usernameResult.Value.Value));

        return Result.Success(member);
    }

    public Result<MemberUsername> AddUsername(
        MemberUsernameId usernameId,
        string value,
        MemberUsernameType usernameType,
        DateTimeOffset? verifiedAtUtc = null)
    {
        Result<MemberUsername> usernameResult = MemberUsername.Create(
            usernameId,
            this.Id,
            this.ScopeId,
            value,
            usernameType);

        if (usernameResult.IsFailure)
        {
            return Result.Failure<MemberUsername>(usernameResult.Error);
        }

        MemberUsername newUsername = usernameResult.Value;
        if (this.usernames.Any(username => username.NormalizedValue == newUsername.NormalizedValue))
        {
            return Result.Failure<MemberUsername>(AuthDomainErrors.UsernameAlreadyExists);
        }

        MemberUsername? current = this.usernames.FirstOrDefault(username =>
            username.UsernameType == usernameType && username.IsActive);

        current?.Deactivate();
        if (verifiedAtUtc is not null)
        {
            newUsername.MarkVerified(verifiedAtUtc.Value);
        }

        this.usernames.Add(newUsername);
        this.Touch();

        return Result.Success(newUsername);
    }

    public bool HasActiveUsername(string username) =>
        MemberUsername.TryNormalize(username, out string? normalizedUsername) &&
        this.usernames.Any(memberUsername =>
            memberUsername.IsActive &&
            memberUsername.NormalizedValue == normalizedUsername);

    public Result Disable(string reason, Guid disabledEventId, DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanDisable();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        if (disabledEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            return Result.Failure(AuthDomainErrors.DisableReasonRequired);
        }

        string trimmedReason = reason.Trim();

        if (trimmedReason.Length > DisabledReasonMaxLength)
        {
            return Result.Failure(AuthDomainErrors.DisableReasonTooLong);
        }

        this.Status = MemberStatus.Disabled;
        this.DisabledAtUtc = nowUtc;
        this.DisabledReason = trimmedReason;
        this.Touch();

        foreach (MemberSession session in this.sessions.Where(session => session.IsActive))
        {
            session.SignOut(nowUtc);
        }

        this.RaiseDomainEvent(new MemberDisabledDomainEvent(
            disabledEventId,
            nowUtc,
            this.Id,
            this.ScopeId,
            trimmedReason));

        return Result.Success();
    }

    public Result Enable(Guid enabledEventId, DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanEnable();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        if (enabledEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        this.Status = MemberStatus.Active;
        this.DisabledAtUtc = null;
        this.DisabledReason = null;
        this.Touch();
        this.RaiseDomainEvent(new MemberEnabledDomainEvent(enabledEventId, nowUtc, this.Id, this.ScopeId));

        return Result.Success();
    }

    private Result EnsureCanAuthenticate() =>
        this.Status switch
        {
            MemberStatus.Active => Result.Success(),
            MemberStatus.Disabled => Result.Failure(AuthDomainErrors.MemberDisabled),
            _ => Result.Failure(AuthDomainErrors.MemberStatusUnknown)
        };

    private Result EnsureCanDisable() =>
        this.Status switch
        {
            MemberStatus.Active => Result.Success(),
            MemberStatus.Disabled => Result.Failure(AuthDomainErrors.MemberAlreadyDisabled),
            _ => Result.Failure(AuthDomainErrors.MemberStatusUnknown)
        };

    private Result EnsureCanEnable() =>
        this.Status switch
        {
            MemberStatus.Disabled => Result.Success(),
            MemberStatus.Active => Result.Failure(AuthDomainErrors.MemberAlreadyActive),
            _ => Result.Failure(AuthDomainErrors.MemberStatusUnknown)
        };

    private Result EnsureKnownStatus() =>
        this.Status is MemberStatus.Active or MemberStatus.Disabled
            ? Result.Success()
            : Result.Failure(AuthDomainErrors.MemberStatusUnknown);

    private void Touch() => this.ConcurrencyStamp = Guid.CreateVersion7();

    private static Result<Member> CreateCore(
        MemberId id,
        string scopeId,
        string? passwordHash,
        DateTimeOffset registeredAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.MemberIdRequired);
        }

        if (string.IsNullOrWhiteSpace(scopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantRequired);
        }

        if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantInvalid);
        }

        return Result.Success(new Member(id, normalizedScopeId, passwordHash)
        {
            RegisteredAtUtc = registeredAtUtc,
            ConcurrencyStamp = Guid.CreateVersion7()
        });
    }
}
