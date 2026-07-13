namespace Gma.Modules.Auth.Domain.Entities;

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed class MemberExternalIdentity : ScopedEntity<MemberExternalIdentityId>
{
    public const int ProviderMaxLength = 64;
    public const int IssuerMaxLength = 512;
    public const int SubjectMaxLength = 512;
    public const int IdentityKeyHashLength = 64;

    private MemberExternalIdentity() { }

    private MemberExternalIdentity(
        MemberExternalIdentityId id,
        MemberId memberId,
        string scopeId,
        string provider,
        string issuer,
        string subject,
        DateTimeOffset linkedAtUtc)
        : base(id, scopeId)
    {
        this.MemberId = memberId;
        this.ProviderCode = NormalizeProvider(provider);
        this.Issuer = issuer.Trim();
        this.Subject = subject.Trim();
        this.IdentityKeyHash = CreateIdentityKeyHash(this.Issuer, this.Subject);
        this.LinkedAtUtc = linkedAtUtc;
        this.LastAuthenticatedAtUtc = linkedAtUtc;
    }

    public MemberId MemberId { get; private set; }
    public string ProviderCode { get; private set; } = string.Empty;
    public string Issuer { get; private set; } = string.Empty;
    public string Subject { get; private set; } = string.Empty;
    public string IdentityKeyHash { get; private set; } = string.Empty;
    public DateTimeOffset LinkedAtUtc { get; private set; }
    public DateTimeOffset? LastAuthenticatedAtUtc { get; private set; }

    internal static Result<MemberExternalIdentity> Create(
        MemberExternalIdentityId id,
        MemberId memberId,
        string scopeId,
        string provider,
        string issuer,
        string subject,
        DateTimeOffset linkedAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<MemberExternalIdentity>(AuthDomainErrors.ExternalIdentityIdRequired);
        }

        if (memberId.Value == Guid.Empty)
        {
            return Result.Failure<MemberExternalIdentity>(AuthDomainErrors.MemberIdRequired);
        }

        if (!ScopeIds.TryNormalize(scopeId, out _))
        {
            return Result.Failure<MemberExternalIdentity>(AuthDomainErrors.TenantInvalid);
        }

        if (!IsValid(provider, ProviderMaxLength) ||
            !IsValid(issuer, IssuerMaxLength) ||
            !IsValid(subject, SubjectMaxLength))
        {
            return Result.Failure<MemberExternalIdentity>(AuthDomainErrors.ExternalIdentityNotValid);
        }

        return Result.Success(new MemberExternalIdentity(
            id,
            memberId,
            scopeId,
            provider,
            issuer,
            subject,
            linkedAtUtc));
    }

    public bool Matches(string issuer, string subject) =>
        string.Equals(this.Issuer, issuer.Trim(), StringComparison.Ordinal) &&
        string.Equals(this.Subject, subject.Trim(), StringComparison.Ordinal);

    internal void MarkAuthenticated(DateTimeOffset nowUtc) => this.LastAuthenticatedAtUtc = nowUtc;

    public static string NormalizeProvider(string provider) => provider.Trim().ToLowerInvariant();

    public static string CreateIdentityKeyHash(string issuer, string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendLengthPrefixed(hash, issuer.Trim());
        AppendLengthPrefixed(hash, subject.Trim());
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void AppendLengthPrefixed(IncrementalHash hash, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    private static bool IsValid(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Trim().Length <= maximumLength &&
        !value.Any(char.IsControl);
}
