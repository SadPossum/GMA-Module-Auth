namespace Gma.Modules.Auth.Domain.Aggregates;

using System.Security.Cryptography;
using System.Text;
using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed class PasswordRecoveryChallenge : ScopedAggregateRoot<PasswordRecoveryChallengeId>
{
    public const int TokenHashMaxLength = MemberSession.RefreshTokenHashMaxLength;

    private PasswordRecoveryChallenge() { }

    private PasswordRecoveryChallenge(
        PasswordRecoveryChallengeId id,
        MemberId memberId,
        string scopeId,
        string email,
        string tokenHash,
        DateTimeOffset requestedAtUtc,
        DateTimeOffset expiresAtUtc)
        : base(id, scopeId)
    {
        this.MemberId = memberId;
        this.Email = email;
        this.TokenHash = tokenHash;
        this.RequestedAtUtc = requestedAtUtc;
        this.ExpiresAtUtc = expiresAtUtc;
        this.ConcurrencyStamp = Guid.CreateVersion7();
    }

    public MemberId MemberId { get; private set; }
    public string Email { get; private set; } = string.Empty;
    public string TokenHash { get; private set; } = string.Empty;
    public DateTimeOffset RequestedAtUtc { get; private set; }
    public DateTimeOffset ExpiresAtUtc { get; private set; }
    public DateTimeOffset? ConsumedAtUtc { get; private set; }
    public DateTimeOffset? RevokedAtUtc { get; private set; }
    public Guid ConcurrencyStamp { get; private set; }

    public static Result<PasswordRecoveryChallenge> Create(
        PasswordRecoveryChallengeId id,
        MemberId memberId,
        string scopeId,
        string email,
        string tokenHash,
        string recoveryCode,
        Guid requestedEventId,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<PasswordRecoveryChallenge>(AuthDomainErrors.PasswordRecoveryChallengeIdRequired);
        }

        if (memberId.Value == Guid.Empty)
        {
            return Result.Failure<PasswordRecoveryChallenge>(AuthDomainErrors.MemberIdRequired);
        }

        if (requestedEventId == Guid.Empty)
        {
            return Result.Failure<PasswordRecoveryChallenge>(AuthDomainErrors.DomainEventIdRequired);
        }

        if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) ||
            !MemberUsername.IsValid(email, Enums.MemberUsernameType.Email) ||
            string.IsNullOrWhiteSpace(tokenHash) ||
            tokenHash.Trim().Length > TokenHashMaxLength ||
            string.IsNullOrWhiteSpace(recoveryCode) ||
            recoveryCode.Trim().Length > TokenHashMaxLength ||
            expiresAtUtc <= nowUtc)
        {
            return Result.Failure<PasswordRecoveryChallenge>(AuthDomainErrors.PasswordRecoveryChallengeNotValid);
        }

        PasswordRecoveryChallenge challenge = new(
            id,
            memberId,
            normalizedScopeId,
            email.Trim(),
            tokenHash.Trim(),
            nowUtc,
            expiresAtUtc);
        challenge.RaiseDomainEvent(new MemberPasswordRecoveryRequestedDomainEvent(
            requestedEventId,
            nowUtc,
            challenge.Id,
            challenge.MemberId,
            challenge.ScopeId,
            challenge.Email,
            recoveryCode.Trim(),
            challenge.ExpiresAtUtc));

        return Result.Success(challenge);
    }

    public bool IsActiveAt(DateTimeOffset nowUtc) =>
        this.ConsumedAtUtc is null && this.RevokedAtUtc is null && this.ExpiresAtUtc > nowUtc;

    public Result Consume(string matchedTokenHash, DateTimeOffset nowUtc)
    {
        if (!this.IsActiveAt(nowUtc) || !HashesEqual(this.TokenHash, matchedTokenHash))
        {
            return Result.Failure(AuthDomainErrors.PasswordRecoveryChallengeInvalid);
        }

        this.ConsumedAtUtc = nowUtc;
        this.Touch();
        return Result.Success();
    }

    public void Revoke(DateTimeOffset nowUtc)
    {
        if (!this.IsActiveAt(nowUtc))
        {
            return;
        }

        this.RevokedAtUtc = nowUtc;
        this.Touch();
    }

    private void Touch() => this.ConcurrencyStamp = Guid.CreateVersion7();

    private static bool HashesEqual(string expected, string candidate)
    {
        byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
        byte[] candidateBytes = Encoding.UTF8.GetBytes(candidate.Trim());
        return expectedBytes.Length == candidateBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, candidateBytes);
    }
}
