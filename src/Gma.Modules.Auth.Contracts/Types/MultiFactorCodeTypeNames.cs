namespace Gma.Modules.Auth.Contracts;

public static class MultiFactorCodeTypeNames
{
    public static string ToWireName(MultiFactorCodeType codeType) =>
        codeType switch
        {
            MultiFactorCodeType.Totp => "totp",
            MultiFactorCodeType.RecoveryCode => "recovery-code",
            _ => throw new ArgumentOutOfRangeException(nameof(codeType), codeType, "Multi-factor code type is invalid."),
        };

    public static bool TryParse(string? value, out MultiFactorCodeType codeType)
    {
        codeType = (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "totp" => MultiFactorCodeType.Totp,
            "recovery-code" => MultiFactorCodeType.RecoveryCode,
            _ => MultiFactorCodeType.Unknown,
        };
        return codeType is not MultiFactorCodeType.Unknown;
    }
}
