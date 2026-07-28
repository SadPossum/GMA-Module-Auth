namespace Gma.Modules.Auth.Application.Security;

using Gma.Framework.Observability;

internal sealed class AuthSecuritySignalDefinitions : ISecuritySignalDefinitionSource
{
    public static readonly SecuritySignalDefinition PasswordProofRateLimited = new(
        "auth.password-proof-rate-limited",
        SecuritySignalCategory.Authentication,
        SecuritySignalSeverity.Warning);

    private static readonly SecuritySignalDefinition[] All =
    [
        PasswordProofRateLimited
    ];

    public IReadOnlyCollection<SecuritySignalDefinition> Definitions => All;
}
