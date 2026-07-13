namespace Gma.Modules.Auth.Domain.Entities;

using Gma.Framework.Naming;
using System.Text.RegularExpressions;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Framework.Domain.Models;
using Gma.Framework.Results;
using System.Security.Cryptography;
using System.Text;

public sealed partial class MemberUsername : ScopedEntity<MemberUsernameId>
{
    public const int ValueMaxLength = 256;
    public const int NormalizedValueMaxLength = ValueMaxLength;
    public const int VerificationTokenHashMaxLength = 512;

    private MemberUsername() { }

    private MemberUsername(
        MemberUsernameId id,
        MemberId memberId,
        string scopeId,
        string value,
        MemberUsernameType usernameType)
        : base(id, scopeId)
    {
        string normalizedValue = Normalize(value);

        this.MemberId = memberId;
        this.Value = value.Trim();
        this.NormalizedValue = normalizedValue;
        this.UsernameType = usernameType;
        this.IsActive = true;
    }

    public MemberId MemberId { get; private set; }
    public string Value { get; private set; } = string.Empty;
    public string NormalizedValue { get; private set; } = string.Empty;
    public MemberUsernameType UsernameType { get; private set; }
    public bool IsActive { get; private set; }
    public DateTimeOffset? VerifiedAtUtc { get; private set; }
    public DateTimeOffset? VerificationRequestedAtUtc { get; private set; }
    public DateTimeOffset? VerificationExpiresAtUtc { get; private set; }
    public string? VerificationTokenHash { get; private set; }
    public bool IsVerified => this.VerifiedAtUtc is not null;

    internal static Result<MemberUsername> Create(
        MemberUsernameId id,
        MemberId memberId,
        string scopeId,
        string value,
        MemberUsernameType usernameType)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<MemberUsername>(AuthDomainErrors.UsernameIdRequired);
        }

        if (memberId.Value == Guid.Empty)
        {
            return Result.Failure<MemberUsername>(AuthDomainErrors.MemberIdRequired);
        }

        if (!ScopeIds.TryNormalize(scopeId, out _))
        {
            return Result.Failure<MemberUsername>(AuthDomainErrors.TenantInvalid);
        }

        if (!IsValid(value, usernameType))
        {
            return Result.Failure<MemberUsername>(AuthDomainErrors.UsernameNotValid);
        }

        return Result.Success(new MemberUsername(id, memberId, scopeId, value.Trim(), usernameType));
    }

    internal void Deactivate() => this.IsActive = false;

    internal Result MarkVerified(DateTimeOffset verifiedAtUtc)
    {
        if (this.UsernameType != MemberUsernameType.Email)
        {
            return Result.Failure(AuthDomainErrors.EmailUsernameNotFound);
        }

        this.VerifiedAtUtc ??= verifiedAtUtc;
        this.ClearVerificationChallenge();
        return Result.Success();
    }

    internal Result RequestVerification(
        string verificationTokenHash,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc)
    {
        if (this.UsernameType != MemberUsernameType.Email || !this.IsActive)
        {
            return Result.Failure(AuthDomainErrors.EmailUsernameNotFound);
        }

        if (this.IsVerified)
        {
            return Result.Failure(AuthDomainErrors.EmailAlreadyVerified);
        }

        if (string.IsNullOrWhiteSpace(verificationTokenHash) ||
            verificationTokenHash.Trim().Length > VerificationTokenHashMaxLength ||
            expiresAtUtc <= nowUtc)
        {
            return Result.Failure(AuthDomainErrors.EmailVerificationTokenNotValid);
        }

        this.VerificationTokenHash = verificationTokenHash.Trim();
        this.VerificationRequestedAtUtc = nowUtc;
        this.VerificationExpiresAtUtc = expiresAtUtc;
        return Result.Success();
    }

    internal Result ConfirmVerification(string verificationTokenHash, DateTimeOffset nowUtc)
    {
        if (this.IsVerified)
        {
            return Result.Success();
        }

        if (this.VerificationExpiresAtUtc is null || this.VerificationExpiresAtUtc <= nowUtc)
        {
            return Result.Failure(AuthDomainErrors.EmailVerificationTokenExpired);
        }

        if (this.VerificationTokenHash is null || !HashesEqual(this.VerificationTokenHash, verificationTokenHash))
        {
            return Result.Failure(AuthDomainErrors.EmailVerificationTokenNotValid);
        }

        this.VerifiedAtUtc = nowUtc;
        this.ClearVerificationChallenge();
        return Result.Success();
    }

    public static string Normalize(string? value) =>
        TryNormalize(value, out string? normalized)
            ? normalized
            : string.Empty;

    public static bool TryNormalize(string? value, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? normalized)
    {
        normalized = null;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string trimmedValue = value.Trim();
        if (trimmedValue.Length > ValueMaxLength)
        {
            return false;
        }

        normalized = trimmedValue.ToUpperInvariant();
        return true;
    }

    public static bool IsValid(string? value, MemberUsernameType usernameType) =>
        TryNormalize(value, out string? normalizedValue) &&
        normalizedValue.Length <= NormalizedValueMaxLength &&
        IsValidUsernameFormat(value!.Trim(), usernameType);

    private static bool IsValidUsernameFormat(string value, MemberUsernameType usernameType) =>
        usernameType switch
        {
            MemberUsernameType.Email => EmailRegex().IsMatch(value),
            MemberUsernameType.Phone => value.Length == 10 && value.All(char.IsDigit),
            _ => false
        };

    private void ClearVerificationChallenge()
    {
        this.VerificationTokenHash = null;
        this.VerificationRequestedAtUtc = null;
        this.VerificationExpiresAtUtc = null;
    }

    private static bool HashesEqual(string expected, string candidate)
    {
        byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
        byte[] candidateBytes = Encoding.UTF8.GetBytes(candidate.Trim());
        return expectedBytes.Length == candidateBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, candidateBytes);
    }

    [GeneratedRegex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")]
    private static partial Regex EmailRegex();
}
