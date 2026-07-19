namespace Gma.Modules.Auth.Api;

using System.Security.Claims;
using System.Text.Json;
using Gma.Framework.Api.Modules;
using Gma.Framework.Api.Observability;
using Gma.Framework.Api.Results;
using Gma.Framework.Api.Scoping;
using Gma.Framework.Cqrs;
using Gma.Framework.ModuleComposition;
using Gma.Framework.Results;
using Gma.Framework.Security;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Queries;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Infrastructure;
using Gma.Modules.Auth.Infrastructure.JwtBearer;
using Gma.Modules.Auth.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public sealed partial class AuthModule
{
    private static IResult ToBrowserAuthResult(
        Result<AuthTokensResponse> result,
        HttpContext httpContext,
        int refreshTokenLifetimeDays)
    {
        if (result.IsFailure)
        {
            return result.ToHttpResult(PublicErrorStatusCodes);
        }

        httpContext.Response.Headers.CacheControl = "no-store";
        httpContext.Response.Headers.Pragma = "no-cache";
        httpContext.Response.Cookies.Append(
            BrowserRefreshCookieName,
            result.Value.RefreshToken,
            CreateBrowserRefreshCookieOptions(httpContext, refreshTokenLifetimeDays));
        httpContext.Response.Cookies.Append(
            BrowserAccessCookieName,
            result.Value.AccessToken,
            CreateBrowserRefreshCookieOptions(httpContext, refreshTokenLifetimeDays));

        return Results.Ok(new BrowserAuthResponse(result.Value.AccessToken));
    }

    private static IResult ToPrimaryAuthenticationHttpResult(
        Result<PrimaryAuthenticationResult> result,
        HttpContext httpContext)
    {
        if (result.IsFailure)
        {
            return result.ToHttpResult(PublicErrorStatusCodes);
        }

        SetNoStoreHeaders(httpContext);
        return result.Value.RequiresMultiFactor
            ? Results.Accepted(value: result.Value.MultiFactorChallenge)
            : Results.Ok(result.Value.Tokens);
    }

    private static IResult ToSecretBearingHttpResult<T>(Result<T> result, HttpContext httpContext)
    {
        if (result.IsSuccess)
        {
            SetNoStoreHeaders(httpContext);
        }

        return result.ToHttpResult(PublicErrorStatusCodes);
    }

    private static IResult ToBrowserPrimaryAuthenticationResult(
        Result<PrimaryAuthenticationResult> result,
        HttpContext httpContext,
        int refreshTokenLifetimeDays)
    {
        if (result.IsFailure)
        {
            return result.ToHttpResult(PublicErrorStatusCodes);
        }

        if (result.Value.RequiresMultiFactor)
        {
            SetNoStoreHeaders(httpContext);
            return Results.Accepted(value: result.Value.MultiFactorChallenge);
        }

        return ToBrowserAuthResult(
            Result.Success(result.Value.Tokens!),
            httpContext,
            refreshTokenLifetimeDays);
    }

    private static IResult ToExternalAuthenticationHttpResult(
        Result<ExternalAuthenticationResponse> result,
        HttpContext httpContext)
    {
        if (result.IsFailure)
        {
            return result.ToHttpResult(PublicErrorStatusCodes);
        }

        if (result.Value.Status is ExternalAuthenticationStatus.Authenticated or ExternalAuthenticationStatus.MultiFactorRequired)
        {
            SetNoStoreHeaders(httpContext);
        }

        return result.Value.Status == ExternalAuthenticationStatus.MultiFactorRequired
            ? Results.Accepted(value: result.Value)
            : Results.Ok(result.Value);
    }

    private static void SetNoStoreHeaders(HttpContext httpContext)
    {
        httpContext.Response.Headers.CacheControl = "no-store";
        httpContext.Response.Headers.Pragma = "no-cache";
    }

    private static void SetBrowserCookies(
        HttpContext httpContext,
        string accessToken,
        string refreshToken,
        int refreshTokenLifetimeDays)
    {
        SetNoStoreHeaders(httpContext);
        httpContext.Response.Cookies.Append(
            BrowserRefreshCookieName,
            refreshToken,
            CreateBrowserRefreshCookieOptions(httpContext, refreshTokenLifetimeDays));
        httpContext.Response.Cookies.Append(
            BrowserAccessCookieName,
            accessToken,
            CreateBrowserRefreshCookieOptions(httpContext, refreshTokenLifetimeDays));
    }

    private static CookieOptions CreateBrowserRefreshCookieOptions(
        HttpContext httpContext,
        int refreshTokenLifetimeDays) =>
        new()
        {
            HttpOnly = true,
            IsEssential = true,
            MaxAge = TimeSpan.FromDays(refreshTokenLifetimeDays),
            Path = BrowserRefreshCookiePath,
            SameSite = SameSiteMode.Strict,
            Secure = httpContext.Request.IsHttps
        };

    private static bool TryGetBrowserCookie(
        HttpContext httpContext,
        string cookieName,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? value) =>
        httpContext.Request.Cookies.TryGetValue(cookieName, out value) &&
        !string.IsNullOrWhiteSpace(value);

    private static void DeleteBrowserCookies(HttpContext httpContext)
    {
        CookieOptions options = new()
        {
            HttpOnly = true,
            IsEssential = true,
            Path = BrowserRefreshCookiePath,
            SameSite = SameSiteMode.Strict,
            Secure = httpContext.Request.IsHttps
        };

        httpContext.Response.Cookies.Delete(BrowserRefreshCookieName, options);
        httpContext.Response.Cookies.Delete(BrowserAccessCookieName, options);
    }

    private static void AddProfileServices(IHostApplicationBuilder builder, AuthProfile profile)
    {
        builder.SelectModuleProfile(profile.Descriptor, "Gma.Modules.Auth.Api");
    }

    private static void RequireScopeWhenNeeded(RouteHandlerBuilder builder, bool requireScope)
    {
        if (requireScope)
        {
            builder.RequireScope();
        }
    }

    private static readonly ApiErrorStatusCodeMap PublicErrorStatusCodes = ApiErrorStatusCodeMap.Create(
        new(AuthApplicationErrors.CredentialsNotValid.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.TokenInvalid.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.PasswordBlocked.Code, StatusCodes.Status400BadRequest),
        new(AuthApplicationErrors.MemberNotFound.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.SessionNotFound.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.SessionInactive.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.RefreshTokenInvalid.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.RefreshTokenExpired.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.RefreshTokenReused.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.SelfRegistrationDisabled.Code, StatusCodes.Status403Forbidden),
        new(AuthApplicationErrors.TenantMismatch.Code, StatusCodes.Status403Forbidden),
        new(AuthApplicationErrors.MemberStatusUnknown.Code, StatusCodes.Status403Forbidden),
        new(AuthApplicationErrors.MemberDisabled.Code, StatusCodes.Status403Forbidden),
        new(AuthApplicationErrors.ExternalExchangeInvalid.Code, StatusCodes.Status400BadRequest),
        new(AuthApplicationErrors.ExternalVerifiedEmailRequired.Code, StatusCodes.Status400BadRequest),
        new(AuthApplicationErrors.ExternalLinkAuthorizationRequired.Code, StatusCodes.Status403Forbidden),
        new(AuthApplicationErrors.FreshAuthenticationRequired.Code, StatusCodes.Status403Forbidden),
        new(AuthApplicationErrors.AlternateAuthenticationRequired.Code, StatusCodes.Status403Forbidden),
        new(AuthApplicationErrors.ExternalIdentityNotFound.Code, StatusCodes.Status404NotFound),
        new(AuthApplicationErrors.PasswordNotConfigured.Code, StatusCodes.Status409Conflict),
        new(AuthApplicationErrors.AuthenticationMethodRequired.Code, StatusCodes.Status409Conflict),
        new(AuthApplicationErrors.EmailUsernameNotFound.Code, StatusCodes.Status404NotFound),
        new(AuthApplicationErrors.EmailAlreadyVerified.Code, StatusCodes.Status409Conflict),
        new(AuthApplicationErrors.EmailVerificationInvalid.Code, StatusCodes.Status400BadRequest),
        new(AuthApplicationErrors.EmailVerificationRequestTooSoon.Code, StatusCodes.Status429TooManyRequests),
        new(AuthApplicationErrors.PasswordRecoveryInvalid.Code, StatusCodes.Status400BadRequest),
        new(AuthApplicationErrors.MultiFactorChallengeInvalid.Code, StatusCodes.Status401Unauthorized),
        new(AuthApplicationErrors.MultiFactorProviderUnavailable.Code, StatusCodes.Status503ServiceUnavailable),
        new(AuthApplicationErrors.TotpAuthenticatorNotActive.Code, StatusCodes.Status409Conflict),
        new(AuthApplicationErrors.TotpAuthenticatorAlreadyActive.Code, StatusCodes.Status409Conflict),
        new(AuthApplicationErrors.TotpEnrollmentInvalid.Code, StatusCodes.Status400BadRequest),
        new(AuthApplicationErrors.UsernameAlreadyExists.Code, StatusCodes.Status409Conflict),
        new(AuthApplicationErrors.ExternalAccountLinkRequired.Code, StatusCodes.Status409Conflict),
        new(AuthApplicationErrors.ExternalIdentityAlreadyLinked.Code, StatusCodes.Status409Conflict));


    public sealed record RegisterMemberApiRequest(string Username, JsonElement UsernameType, string Password);

    private static Guid? GetMemberId(ClaimsPrincipal user)
    {
        string? memberId = user.FindFirstValue(ApplicationClaimNames.Subject) ??
            user.FindFirstValue(ClaimTypes.NameIdentifier);

        return Guid.TryParse(memberId, out Guid parsed)
            ? parsed
            : null;
    }

    private static Guid? GetSessionId(ClaimsPrincipal user)
    {
        string? sessionId = user.FindFirstValue(ApplicationClaimNames.SessionId);

        return Guid.TryParse(sessionId, out Guid parsed)
            ? parsed
            : null;
    }

    private static string? GetClientIpAddress(HttpContext httpContext) =>
        httpContext.Connection.RemoteIpAddress?.ToString();

    private static string? GetUserAgent(HttpContext httpContext) =>
        httpContext.Request.Headers.UserAgent.ToString();

    private bool TokenTenantMatches(ClaimsPrincipal user, IAuthScopeContext scopeContext)
    {
        if (!this.profile.RequiresScopeContext)
        {
            return true;
        }

        if (!scopeContext.IsEnabled)
        {
            return true;
        }

        string? tokenScopeId = user.FindFirstValue(ApplicationClaimNames.ScopeId);

        return !string.IsNullOrWhiteSpace(tokenScopeId) &&
               string.Equals(tokenScopeId, scopeContext.ScopeId, StringComparison.Ordinal);
    }
}
