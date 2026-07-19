namespace Gma.Modules.Auth.Domain.Entities;

using System.Security.Cryptography;
using System.Text;
using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed class MemberTotpRecoveryCode : ScopedEntity<MemberTotpRecoveryCodeId>
{
    public const int HashMaxLength = MemberSession.RefreshTokenHashMaxLength;

    private MemberTotpRecoveryCode() { }

    private MemberTotpRecoveryCode(
        MemberTotpRecoveryCodeId id,
        MemberTotpAuthenticatorId authenticatorId,
        MemberId memberId,
        string scopeId,
        string hash,
        DateTimeOffset generatedAtUtc)
        : base(id, scopeId)
    {
        this.AuthenticatorId = authenticatorId;
        this.MemberId = memberId;
        this.Hash = hash;
        this.GeneratedAtUtc = generatedAtUtc;
    }

    public MemberTotpAuthenticatorId AuthenticatorId { get; private set; }
    public MemberId MemberId { get; private set; }
    public string Hash { get; private set; } = string.Empty;
    public DateTimeOffset GeneratedAtUtc { get; private set; }
    public DateTimeOffset? ConsumedAtUtc { get; private set; }
    public DateTimeOffset? RevokedAtUtc { get; private set; }
    public bool IsAvailable => this.ConsumedAtUtc is null && this.RevokedAtUtc is null;

    internal static Result<MemberTotpRecoveryCode> Create(
        MemberTotpRecoveryCodeId id,
        MemberTotpAuthenticatorId authenticatorId,
        MemberId memberId,
        string scopeId,
        string hash,
        DateTimeOffset generatedAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<MemberTotpRecoveryCode>(AuthDomainErrors.TotpRecoveryCodeIdRequired);
        }

        if (authenticatorId.Value == Guid.Empty || memberId.Value == Guid.Empty ||
            !ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) ||
            !TryNormalizeHash(hash, out string? normalizedHash))
        {
            return Result.Failure<MemberTotpRecoveryCode>(AuthDomainErrors.TotpRecoveryCodesInvalid);
        }

        return Result.Success(new MemberTotpRecoveryCode(
            id,
            authenticatorId,
            memberId,
            normalizedScopeId,
            normalizedHash,
            generatedAtUtc));
    }

    internal bool MatchesAny(IReadOnlyCollection<string> candidateHashes) =>
        this.IsAvailable && candidateHashes.Any(this.MatchesHash);

    internal void Consume(DateTimeOffset nowUtc) => this.ConsumedAtUtc = nowUtc;

    internal void Revoke(DateTimeOffset nowUtc)
    {
        if (this.IsAvailable)
        {
            this.RevokedAtUtc = nowUtc;
        }
    }

    private bool MatchesHash(string candidate)
    {
        byte[] expectedBytes = Encoding.UTF8.GetBytes(this.Hash);
        byte[] candidateBytes = Encoding.UTF8.GetBytes(candidate.Trim());
        return expectedBytes.Length == candidateBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, candidateBytes);
    }

    private static bool TryNormalizeHash(
        string? value,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? normalized)
    {
        normalized = value?.Trim();
        return !string.IsNullOrWhiteSpace(normalized) && normalized.Length <= HashMaxLength;
    }
}
