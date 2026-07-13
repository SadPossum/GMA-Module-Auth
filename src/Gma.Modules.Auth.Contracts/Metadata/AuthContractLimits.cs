namespace Gma.Modules.Auth.Contracts;

public static class AuthContractLimits
{
    public const int UsernameMaxLength = 256;
    public const int DisableReasonMaxLength = 512;
    public const int AuthenticationMethodMaxLength = 256;
    public const int VerificationCodeMaxLength = 2_048;
    public const int IpAddressMaxLength = 64;
    public const int UserAgentMaxLength = 512;
}
