namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using System.Security.Cryptography;
using System.Text.Json;
using Gma.Framework.Naming;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

internal sealed class ExternalAuthenticationChallengeHandoff
{
    internal const string StartPath = "/api/auth/external/challenge";
    private const string CookiePrefix = "gma.auth.external-handoff.";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    private readonly IDataProtector protector;
    private readonly TimeProvider timeProvider;

    public ExternalAuthenticationChallengeHandoff(
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        this.protector = dataProtectionProvider.CreateProtector(
            "Gma.Modules.Auth.Providers.OpenIdConnect.ExternalAuthenticationChallengeHandoff.v1");
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public ExternalAuthenticationChallengeResponse Issue(
        HttpContext httpContext,
        string provider,
        string returnUrl,
        string? scopeId,
        ExternalAuthenticationIntent intent,
        Guid? targetMemberId,
        Guid? targetSessionId)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        DateTimeOffset issuedAtUtc = this.timeProvider.GetUtcNow();
        var payload = new ChallengePayload(
            nonce,
            OpenIdConnectProviderRegistry.NormalizeProviderKey(provider),
            returnUrl,
            ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) ? normalizedScopeId : null,
            intent,
            targetMemberId,
            targetSessionId,
            issuedAtUtc,
            issuedAtUtc.Add(Lifetime));
        string protectedPayload = this.protector.Protect(JsonSerializer.Serialize(payload));

        httpContext.Response.Cookies.Append(
            CookieName(nonce),
            protectedPayload,
            CreateCookieOptions(httpContext, Lifetime));

        return new ExternalAuthenticationChallengeResponse($"{StartPath}/{nonce}");
    }

    public bool TryConsume(HttpContext httpContext, string nonce, out ChallengePayload? payload)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        payload = null;
        if (!Guid.TryParseExact(nonce, "N", out _))
        {
            return false;
        }

        string cookieName = CookieName(nonce);
        if (!httpContext.Request.Cookies.TryGetValue(cookieName, out string? protectedPayload) ||
            string.IsNullOrWhiteSpace(protectedPayload))
        {
            return false;
        }

        httpContext.Response.Cookies.Delete(cookieName, CreateCookieOptions(httpContext, maxAge: null));
        try
        {
            ChallengePayload? candidate = JsonSerializer.Deserialize<ChallengePayload>(
                this.protector.Unprotect(protectedPayload));
            DateTimeOffset now = this.timeProvider.GetUtcNow();
            if (candidate is null ||
                !string.Equals(candidate.Nonce, nonce, StringComparison.Ordinal) ||
                candidate.IssuedAtUtc > now.AddMinutes(1) ||
                candidate.ExpiresAtUtc <= now ||
                !OpenIdConnectProviderRegistry.IsValidProviderKey(candidate.ProviderKey) ||
                string.IsNullOrWhiteSpace(candidate.ReturnUrl))
            {
                return false;
            }

            payload = candidate;
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            return false;
        }
    }

    private static string CookieName(string nonce) => CookiePrefix + nonce;

    private static CookieOptions CreateCookieOptions(HttpContext httpContext, TimeSpan? maxAge) =>
        new()
        {
            HttpOnly = true,
            IsEssential = true,
            MaxAge = maxAge,
            Path = StartPath,
            SameSite = SameSiteMode.Strict,
            Secure = httpContext.Request.IsHttps,
        };

    internal sealed record ChallengePayload(
        string Nonce,
        string ProviderKey,
        string ReturnUrl,
        string? ScopeId,
        ExternalAuthenticationIntent Intent,
        Guid? TargetMemberId,
        Guid? TargetSessionId,
        DateTimeOffset IssuedAtUtc,
        DateTimeOffset ExpiresAtUtc);
}
