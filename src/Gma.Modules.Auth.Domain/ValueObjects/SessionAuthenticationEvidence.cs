namespace Gma.Modules.Auth.Domain.ValueObjects;

using System.Collections.ObjectModel;

public sealed record SessionAuthenticationEvidence
{
    public const int ContextReferenceMaxLength = 256;
    public const int MethodReferenceMaxLength = 64;
    public const int MethodReferenceLimit = 16;

    private readonly ReadOnlyCollection<string> methodReferences;

    public SessionAuthenticationEvidence(
        string contextReference,
        IEnumerable<string> methodReferences,
        DateTimeOffset authenticatedAtUtc)
    {
        this.ContextReference = NormalizeIdentifier(
            contextReference,
            ContextReferenceMaxLength,
            nameof(contextReference));
        this.methodReferences = NormalizeMethodReferences(methodReferences);
        this.AuthenticatedAtUtc = authenticatedAtUtc.ToUniversalTime();
    }

    public string ContextReference { get; }
    public IReadOnlyList<string> MethodReferences => this.methodReferences;
    public DateTimeOffset AuthenticatedAtUtc { get; }

    public static SessionAuthenticationEvidence Password(DateTimeOffset authenticatedAtUtc) =>
        new(AuthenticationContextReferences.Password, [AuthenticationMethodReferences.Password], authenticatedAtUtc);

    public static SessionAuthenticationEvidence External(DateTimeOffset authenticatedAtUtc) =>
        new(
            AuthenticationContextReferences.External,
            [AuthenticationMethodReferences.External],
            authenticatedAtUtc);

    public static SessionAuthenticationEvidence CompleteWithTotp(
        SessionAuthenticationEvidence primaryEvidence,
        DateTimeOffset authenticatedAtUtc) =>
        CompleteSecondStep(primaryEvidence, AuthenticationMethodReferences.OneTimePassword, authenticatedAtUtc);

    public static SessionAuthenticationEvidence CompleteWithRecoveryCode(
        SessionAuthenticationEvidence primaryEvidence,
        DateTimeOffset authenticatedAtUtc) =>
        CompleteSecondStep(primaryEvidence, AuthenticationMethodReferences.RecoveryCode, authenticatedAtUtc);

    public static SessionAuthenticationEvidence Legacy(DateTimeOffset authenticatedAtUtc) =>
        new(AuthenticationContextReferences.Legacy, [], authenticatedAtUtc);

    private static SessionAuthenticationEvidence CompleteSecondStep(
        SessionAuthenticationEvidence primaryEvidence,
        string secondStepMethod,
        DateTimeOffset authenticatedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(primaryEvidence);

        bool passwordPrimary = string.Equals(
            primaryEvidence.ContextReference,
            AuthenticationContextReferences.Password,
            StringComparison.Ordinal);
        string contextReference = passwordPrimary
            ? AuthenticationContextReferences.MultiFactor
            : AuthenticationContextReferences.TwoStep;
        List<string> methods = [.. primaryEvidence.MethodReferences, secondStepMethod];
        if (passwordPrimary)
        {
            methods.Add(AuthenticationMethodReferences.MultiFactor);
        }

        return new SessionAuthenticationEvidence(contextReference, methods, authenticatedAtUtc);
    }

    private static ReadOnlyCollection<string> NormalizeMethodReferences(IEnumerable<string> methodReferences)
    {
        ArgumentNullException.ThrowIfNull(methodReferences);

        List<string> normalized = [];
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (string methodReference in methodReferences)
        {
            string candidate = NormalizeIdentifier(
                methodReference,
                MethodReferenceMaxLength,
                nameof(methodReferences));
            if (seen.Add(candidate))
            {
                normalized.Add(candidate);
            }
        }

        if (normalized.Count > MethodReferenceLimit)
        {
            throw new ArgumentException(
                $"Authentication evidence cannot contain more than {MethodReferenceLimit} method references.",
                nameof(methodReferences));
        }

        return normalized.AsReadOnly();
    }

    private static string NormalizeIdentifier(string value, int maxLength, string parameterName)
    {
        string candidate = value?.Trim() ?? string.Empty;
        if (candidate.Length == 0 ||
            candidate.Length > maxLength ||
            candidate.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new ArgumentException(
                $"Authentication evidence values are required, must be {maxLength} characters or fewer, and cannot contain whitespace or control characters.",
                parameterName);
        }

        return candidate;
    }
}
