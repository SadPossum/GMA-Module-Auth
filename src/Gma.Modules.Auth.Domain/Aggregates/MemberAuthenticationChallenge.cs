namespace Gma.Modules.Auth.Domain.Aggregates;

using System.Security.Cryptography;
using System.Text;
using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed class MemberAuthenticationChallenge : ScopedAggregateRoot<MemberAuthenticationChallengeId>
{
    public const int TokenHashMaxLength = MemberSession.RefreshTokenHashMaxLength;
    public const int IpAddressMaxLength = 64;
    public const int UserAgentMaxLength = 512;
    public const int MaximumAttemptLimit = 20;

    private string[] primaryAuthenticationMethodReferences = [];

    private MemberAuthenticationChallenge() { }

    private MemberAuthenticationChallenge(
        MemberAuthenticationChallengeId id,
        MemberId memberId,
        string scopeId,
        string tokenHash,
        string primaryAuthenticationMethod,
        SessionAuthenticationEvidence primaryEvidence,
        string? ipAddress,
        string? userAgent,
        int maximumAttempts,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc)
        : base(id, scopeId)
    {
        this.MemberId = memberId;
        this.TokenHash = tokenHash;
        this.PrimaryAuthenticationMethod = primaryAuthenticationMethod;
        this.PrimaryAuthenticationContextReference = primaryEvidence.ContextReference;
        this.SetPrimaryAuthenticationMethodReferences(primaryEvidence.MethodReferences);
        this.PrimaryAuthenticatedAtUtc = primaryEvidence.AuthenticatedAtUtc;
        this.IpAddress = ipAddress;
        this.UserAgent = userAgent;
        this.MaximumAttempts = maximumAttempts;
        this.CreatedAtUtc = nowUtc;
        this.ExpiresAtUtc = expiresAtUtc;
        this.ConcurrencyStamp = Guid.CreateVersion7();
    }

    public MemberId MemberId { get; private set; }
    public string TokenHash { get; private set; } = string.Empty;
    public string PrimaryAuthenticationMethod { get; private set; } = string.Empty;
    public string PrimaryAuthenticationContextReference { get; private set; } = string.Empty;
    public IReadOnlyList<string> PrimaryAuthenticationMethodReferences => this.primaryAuthenticationMethodReferences;
    public DateTimeOffset PrimaryAuthenticatedAtUtc { get; private set; }
    public string? IpAddress { get; private set; }
    public string? UserAgent { get; private set; }
    public int FailedAttemptCount { get; private set; }
    public int MaximumAttempts { get; private set; }
    public DateTimeOffset CreatedAtUtc { get; private set; }
    public DateTimeOffset ExpiresAtUtc { get; private set; }
    public DateTimeOffset? ConsumedAtUtc { get; private set; }
    public DateTimeOffset? RevokedAtUtc { get; private set; }
    public Guid ConcurrencyStamp { get; private set; }
    public SessionAuthenticationEvidence PrimaryEvidence => new(
        this.PrimaryAuthenticationContextReference,
        this.primaryAuthenticationMethodReferences,
        this.PrimaryAuthenticatedAtUtc);

    public static Result<MemberAuthenticationChallenge> Create(
        MemberAuthenticationChallengeId id,
        MemberId memberId,
        string scopeId,
        string tokenHash,
        string primaryAuthenticationMethod,
        SessionAuthenticationEvidence primaryEvidence,
        string? ipAddress,
        string? userAgent,
        int maximumAttempts,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(primaryEvidence);
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<MemberAuthenticationChallenge>(AuthDomainErrors.AuthenticationChallengeIdRequired);
        }

        if (memberId.Value == Guid.Empty ||
            !ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) ||
            !TryNormalizeTokenHash(tokenHash, out string? normalizedTokenHash) ||
            !TryNormalizePrimaryMethod(primaryAuthenticationMethod, primaryEvidence, out string? normalizedMethod) ||
            !TryNormalizeOptional(ipAddress, IpAddressMaxLength, out string? normalizedIpAddress) ||
            !TryNormalizeOptional(userAgent, UserAgentMaxLength, out string? normalizedUserAgent) ||
            maximumAttempts is < 1 or > MaximumAttemptLimit ||
            primaryEvidence.AuthenticatedAtUtc > nowUtc ||
            expiresAtUtc <= nowUtc)
        {
            return Result.Failure<MemberAuthenticationChallenge>(AuthDomainErrors.AuthenticationChallengeNotValid);
        }

        return Result.Success(new MemberAuthenticationChallenge(
            id,
            memberId,
            normalizedScopeId,
            normalizedTokenHash,
            normalizedMethod,
            primaryEvidence,
            normalizedIpAddress,
            normalizedUserAgent,
            maximumAttempts,
            expiresAtUtc,
            nowUtc));
    }

    public bool IsActiveAt(DateTimeOffset nowUtc) =>
        this.ConsumedAtUtc is null &&
        this.RevokedAtUtc is null &&
        this.ExpiresAtUtc > nowUtc &&
        this.FailedAttemptCount < this.MaximumAttempts;

    public bool MatchesTokenHash(string candidateHash)
    {
        byte[] expectedBytes = Encoding.UTF8.GetBytes(this.TokenHash);
        byte[] candidateBytes = Encoding.UTF8.GetBytes(candidateHash.Trim());
        return expectedBytes.Length == candidateBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, candidateBytes);
    }

    public Result RecordFailure(DateTimeOffset nowUtc)
    {
        if (!this.IsActiveAt(nowUtc))
        {
            return Result.Failure(AuthDomainErrors.AuthenticationChallengeInvalid);
        }

        this.FailedAttemptCount++;
        if (this.FailedAttemptCount >= this.MaximumAttempts)
        {
            this.RevokedAtUtc = nowUtc;
        }

        this.Touch();
        return Result.Failure(AuthDomainErrors.AuthenticationChallengeInvalid);
    }

    public Result Consume(string matchedTokenHash, DateTimeOffset nowUtc)
    {
        if (!this.IsActiveAt(nowUtc) || !this.MatchesTokenHash(matchedTokenHash))
        {
            return Result.Failure(AuthDomainErrors.AuthenticationChallengeInvalid);
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

    private static bool TryNormalizePrimaryMethod(
        string? method,
        SessionAuthenticationEvidence evidence,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? normalized)
    {
        normalized = null;
        if (!MemberAuthenticationMethods.TryNormalize(method, out string candidate) ||
            string.Equals(candidate, MemberAuthenticationMethods.Totp, StringComparison.Ordinal))
        {
            return false;
        }

        string expectedContext = string.Equals(candidate, MemberAuthenticationMethods.Password, StringComparison.Ordinal)
            ? AuthenticationContextReferences.Password
            : AuthenticationContextReferences.External;
        if (!string.Equals(evidence.ContextReference, expectedContext, StringComparison.Ordinal))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }

    private static bool TryNormalizeTokenHash(
        string? value,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? normalized)
    {
        normalized = value?.Trim();
        return !string.IsNullOrWhiteSpace(normalized) && normalized.Length <= TokenHashMaxLength;
    }

    private static bool TryNormalizeOptional(
        string? value,
        int maximumLength,
        out string? normalized)
    {
        normalized = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        return normalized is null ||
               (normalized.Length <= maximumLength && !normalized.Any(char.IsControl));
    }

    private void SetPrimaryAuthenticationMethodReferences(IEnumerable<string> methodReferences) =>
        this.primaryAuthenticationMethodReferences = [.. methodReferences];
}
