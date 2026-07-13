namespace Gma.Modules.Auth.Application.ExternalAuthentication;

using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;

public sealed record ValidatedExternalIdentity
{
    public ValidatedExternalIdentity(
        string provider,
        string issuer,
        string subject,
        string? email,
        bool emailVerified)
    {
        this.ProviderCode = MemberExternalIdentity.NormalizeProvider(NormalizeRequired(
            provider,
            MemberExternalIdentity.ProviderMaxLength,
            nameof(provider)));
        this.Issuer = NormalizeRequired(issuer, MemberExternalIdentity.IssuerMaxLength, nameof(issuer));
        this.Subject = NormalizeRequired(subject, MemberExternalIdentity.SubjectMaxLength, nameof(subject));
        this.Email = MemberUsername.IsValid(email, MemberUsernameType.Email) ? email!.Trim() : null;
        this.EmailVerified = this.Email is not null && emailVerified;
    }

    public string ProviderCode { get; }
    public string Issuer { get; }
    public string Subject { get; }
    public string? Email { get; }
    public bool EmailVerified { get; }

    private static string NormalizeRequired(string value, int maximumLength, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        string normalized = value.Trim();
        if (normalized.Length > maximumLength)
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }

        if (normalized.Any(char.IsControl))
        {
            throw new ArgumentException("External identity values cannot contain control characters.", parameterName);
        }

        return normalized;
    }
}
