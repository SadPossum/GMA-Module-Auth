namespace Gma.Modules.Auth.Application.Security;

internal static class AuthPasswordPolicy
{
    public const int MinimumLength = 15;
    public const int MaximumLength = 128;
    public const string MinimumLengthMessage = "Password must contain at least 15 characters.";
    public const string MaximumLengthMessage = "Password must contain no more than 128 characters.";

    public static bool IsValidPlaintextPassword(string? password) =>
        !string.IsNullOrEmpty(password) &&
        password.Length >= MinimumLength &&
        password.Length <= MaximumLength;
}
