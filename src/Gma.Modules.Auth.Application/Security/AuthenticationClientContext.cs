namespace Gma.Modules.Auth.Application.Security;

using Gma.Modules.Auth.Contracts;

internal static class AuthenticationClientContext
{
    public static string? NormalizeIpAddress(string? value) => Normalize(value, AuthContractLimits.IpAddressMaxLength);

    public static string? NormalizeUserAgent(string? value) => Normalize(value, AuthContractLimits.UserAgentMaxLength);

    private static string? Normalize(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string normalized = new([.. value.Trim().Where(character => !char.IsControl(character))]);
        if (normalized.Length == 0)
        {
            return null;
        }

        return normalized.Length <= maximumLength ? normalized : normalized[..maximumLength];
    }
}
