namespace Gma.Modules.Auth.Api;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed class RememberedBrowserHttpSecurity(IDataProtectionProvider protection, ISystemClock clock)
{
    private readonly IDataProtector csrf = protection.CreateProtector("Gma.Auth.RememberedBrowser.Csrf.v1");

    internal static bool ReadDevice(HttpContext context, RememberedBrowserRequestContext request)
    {
        string[] values = context.Request.Headers.Cookie.ToString().Split(';', StringSplitOptions.TrimEntries)
            .Where(value => value.StartsWith(RememberedBrowserHttp.DeviceCookieName + "=", StringComparison.Ordinal))
            .ToArray();
        if (values.Length > 1)
        {
            return false;
        }

        request.DeviceCredential = values.Length == 0 ? null : values[0][(RememberedBrowserHttp.DeviceCookieName.Length + 1)..];
        request.ExpectedGeneration = context.Request.Headers.TryGetValue(RememberedBrowserHttp.GenerationHeaderName, out var generation) &&
            generation.Count == 1 && long.TryParse(generation[0], NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) && parsed > 0
                ? parsed : null;
        request.IsRememberedOperation = context.Request.Path.StartsWithSegments("/api/auth/browser/remembered");
        request.IsBrowserTransport = context.Request.Path.StartsWithSegments("/api/auth/browser");
        return request.DeviceCredential is null ||
            (request.DeviceCredential.Length == 64 && request.DeviceCredential.All(char.IsAsciiHexDigit));
    }

    internal static bool SameOrigin(HttpContext context)
    {
        if (!context.Request.IsHttps)
        {
            return false;
        }

        string fetch = context.Request.Headers["Sec-Fetch-Site"].ToString();
        if (fetch.Length > 0 && fetch is not ("same-origin" or "none"))
        {
            return false;
        }

        var origins = context.Request.Headers.Origin;
        return origins.Count == 1 && Uri.TryCreate(origins[0], UriKind.Absolute, out Uri? origin) &&
            origin.Scheme == Uri.UriSchemeHttps && origin.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped)
                .Equals(context.Request.Scheme + "://" + context.Request.Host.Value, StringComparison.OrdinalIgnoreCase) &&
            origin.AbsolutePath == "/" && origin.Query.Length == 0 && origin.Fragment.Length == 0 && origin.UserInfo.Length == 0;
    }

    internal RememberedBrowserCurrentResponse WithCsrf(RememberedBrowserCurrentResponse current, string? credential)
    {
        if (credential is null || current.Generation <= 0 ||
            current.State is RememberedBrowserState.Missing or RememberedBrowserState.Revoked or RememberedBrowserState.Unavailable)
        {
            return current;
        }

        string payload = JsonSerializer.Serialize(new CsrfProof(Digest(credential), current.Generation, clock.UtcNow.AddMinutes(10)));
        return current with { CsrfToken = this.csrf.Protect(payload) };
    }

    internal bool ValidateCsrf(HttpContext context, RememberedBrowserRequestContext request, long generation)
    {
        var header = context.Request.Headers[RememberedBrowserHttp.CsrfHeaderName];
        if (header.Count != 1 || header[0] is not { Length: > 0 and <= 2048 } token ||
            request.DeviceCredential is null || request.ExpectedGeneration != generation)
        {
            return false;
        }

        try
        {
            CsrfProof? proof = JsonSerializer.Deserialize<CsrfProof>(this.csrf.Unprotect(token));
            return proof is not null && proof.Generation == generation && proof.ExpiresAtUtc > clock.UtcNow &&
                proof.ExpiresAtUtc <= clock.UtcNow.AddMinutes(10) &&
                CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(proof.DeviceHash),
                    Encoding.UTF8.GetBytes(Digest(request.DeviceCredential)));
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or FormatException)
        {
            return false;
        }
    }

    internal static void ClearCookies(HttpContext context, bool device)
    {
        CookieOptions cookie = new() { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, Path = "/api/auth/browser" };
        context.Response.Cookies.Delete("gma.auth.access", cookie);
        context.Response.Cookies.Delete("gma.auth.refresh", cookie);
        if (device)
        {
            cookie.Path = RememberedBrowserHttp.DeviceCookiePath;
            context.Response.Cookies.Delete(RememberedBrowserHttp.DeviceCookieName, cookie);
        }
    }

    internal static void WriteCookies(HttpContext context, RememberedBrowserCompletion completion)
    {
        CookieOptions cookie = new()
        {
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            IsEssential = true,
            Path = "/api/auth/browser",
            Expires = completion.CookieExpiresAtUtc
        };
        if (completion.RefreshToken is not null && completion.Response.AccessToken is not null)
        {
            context.Response.Cookies.Append("gma.auth.access", completion.Response.AccessToken, cookie);
            context.Response.Cookies.Append("gma.auth.refresh", completion.RefreshToken, cookie);
        }

        if (completion.DeviceCredential is not null)
        {
            cookie.Path = RememberedBrowserHttp.DeviceCookiePath;
            context.Response.Cookies.Append(RememberedBrowserHttp.DeviceCookieName, completion.DeviceCredential, cookie);
        }
    }

    private static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private sealed record CsrfProof(string DeviceHash, long Generation, DateTimeOffset ExpiresAtUtc);
}

public static class RememberedBrowserHttpApplicationBuilderExtensions
{
    public static IApplicationBuilder UseAuthRememberedBrowserSecurity(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.Use(async (context, continuation) =>
        {
            RememberedBrowserOptions options = context.RequestServices.GetRequiredService<IOptions<RememberedBrowserOptions>>().Value;
            if (!options.Enabled)
            {
                await continuation(context).ConfigureAwait(false);
                return;
            }

            RememberedBrowserRequestContext request = context.RequestServices.GetRequiredService<RememberedBrowserRequestContext>();
            bool valid = RememberedBrowserHttpSecurity.ReadDevice(context, request);
            bool authPath = context.Request.Path.StartsWithSegments("/api/auth");
            bool protectedPath = request.IsRememberedOperation || (authPath && request.DeviceCredential is not null);
            if (!valid || (protectedPath && !context.Request.IsHttps))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.Headers.CacheControl = "no-store";
                return;
            }

            if (protectedPath && !HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
            {
                if (!RememberedBrowserHttpSecurity.SameOrigin(context))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return;
                }

                bool bootstrap = context.Request.Path.Equals("/api/auth/browser/remembered/device");
                if (!bootstrap || request.DeviceCredential is not null)
                {
                    IRememberedBrowserService service = context.RequestServices.GetRequiredService<IRememberedBrowserService>();
                    RememberedBrowserCurrentResponse current = await service.CurrentAsync(context.RequestAborted).ConfigureAwait(false);
                    RememberedBrowserHttpSecurity security = context.RequestServices.GetRequiredService<RememberedBrowserHttpSecurity>();
                    if (current.Generation <= 0 || !security.ValidateCsrf(context, request, current.Generation))
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        return;
                    }
                }
            }

            try
            {
                await continuation(context).ConfigureAwait(false);
            }
            catch (RememberedBrowserStateChangedException)
            {
                context.Response.StatusCode = StatusCodes.Status409Conflict;
                context.Response.Headers.CacheControl = "no-store";
            }
        });
        return app;
    }
}
