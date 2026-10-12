namespace Gma.Modules.Auth.Contracts;

public static class RememberedBrowserHttp
{
    public const string DeviceCookieName = "__Secure-gma.auth.device";
    public const string DeviceCookiePath = "/api";
    public const string CsrfHeaderName = "X-Gma-Remembered-CSRF";
    public const string GenerationHeaderName = "X-Gma-Remembered-Generation";
}
