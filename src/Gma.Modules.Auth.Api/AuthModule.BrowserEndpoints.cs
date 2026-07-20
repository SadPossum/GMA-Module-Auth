namespace Gma.Modules.Auth.Api;

using System.Security.Claims;
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
    private void MapBrowserEndpoints(RouteGroupBuilder authGroup, bool requireScope)
    {
        RouteGroupBuilder browser = authGroup.MapGroup("/browser");

        RouteHandlerBuilder register = browser.MapPost("/register", async (
            RegisterMemberRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            Result<AuthTokensResponse> result = await dispatcher.SendAsync(
                new RegisterMemberCommand(
                    request.Username,
                    request.UsernameType,
                    request.Password),
                cancellationToken).ConfigureAwait(false);

            return ToBrowserAuthResult(result, httpContext, options.Value.RefreshTokenLifetimeDays);
        });
        register.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(register, requireScope);

        RouteHandlerBuilder login = browser.MapPost("/login", async (
            LoginMemberRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            Result<PrimaryAuthenticationResult> result = await dispatcher.SendAsync(
                new LoginMemberCommand(
                    request.Username,
                    request.Password,
                    GetClientIpAddress(httpContext),
                    GetUserAgent(httpContext)),
                cancellationToken).ConfigureAwait(false);

            return ToBrowserPrimaryAuthenticationResult(
                result,
                httpContext,
                options.Value.RefreshTokenLifetimeDays);
        });
        login.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        login.Produces<MultiFactorChallengeResponse>(StatusCodes.Status202Accepted);
        RequireScopeWhenNeeded(login, requireScope);

        RouteHandlerBuilder refresh = browser.MapPost("/refresh", async (
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            if (!TryGetBrowserCookie(httpContext, BrowserAccessCookieName, out string? accessToken) ||
                !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
            {
                return Results.Unauthorized();
            }

            Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await dispatcher.SendAsync(
                new RefreshMemberSessionCommand(accessToken, refreshToken),
                cancellationToken).ConfigureAwait(false);

            if (result.IsFailure)
            {
                DeleteBrowserCookies(httpContext);
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (result.Value.RefreshTokenReuseDetected)
            {
                DeleteBrowserCookies(httpContext);
                return ToRefreshTokenReuseHttpResult();
            }

            return ToBrowserAuthResult(
                Result.Success(result.Value.Response),
                httpContext,
                options.Value.RefreshTokenLifetimeDays);
        });
        refresh.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(refresh, requireScope);

        RouteHandlerBuilder passwordStepUp = browser.MapPost("/step-up/password", async (
            BrowserPasswordStepUpRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId ||
                !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
            {
                return Results.Unauthorized();
            }

            Result<RefreshTokenBoundCompletion<AuthTokensResponse>> result = await dispatcher.SendAsync(
                new StepUpWithPasswordCommand(memberId, sessionId, request.Password, refreshToken),
                cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (result.Value.RefreshTokenReuseDetected)
            {
                DeleteBrowserCookies(httpContext);
                return ToRefreshTokenReuseHttpResult();
            }

            return ToBrowserAuthResult(
                Result.Success(result.Value.Response),
                httpContext,
                options.Value.RefreshTokenLifetimeDays);
        })
            .RequireAuthorization();
        passwordStepUp.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(passwordStepUp, requireScope);

        RouteHandlerBuilder setPassword = browser.MapPut("/password", async (
            BrowserSetPasswordRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId ||
                !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
            {
                return Results.Unauthorized();
            }

            return ToBrowserRefreshTokenBoundAuthResult(
                await dispatcher.SendAsync(
                    new SetMemberPasswordCommand(
                        memberId,
                        sessionId,
                        request.NewPassword,
                        request.CurrentPassword,
                        refreshToken),
                    cancellationToken).ConfigureAwait(false),
                httpContext,
                options.Value.RefreshTokenLifetimeDays);
        })
            .RequireAuthorization();
        setPassword.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(setPassword, requireScope);

        RouteHandlerBuilder removePassword = browser.MapPost("/password/remove", async (
            BrowserRemovePasswordRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId ||
                !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
            {
                return Results.Unauthorized();
            }

            return ToBrowserRefreshTokenBoundAuthResult(
                await dispatcher.SendAsync(
                    new RemoveMemberPasswordCommand(
                        memberId,
                        sessionId,
                        request.CurrentPassword,
                        refreshToken),
                    cancellationToken).ConfigureAwait(false),
                httpContext,
                options.Value.RefreshTokenLifetimeDays);
        })
            .RequireAuthorization();
        removePassword.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(removePassword, requireScope);

        RouteHandlerBuilder unlinkIdentity = browser.MapPost(
            "/external-identities/{externalIdentityId:guid}/unlink",
            async (
                Guid externalIdentityId,
                BrowserUnlinkExternalIdentityRequest request,
                ClaimsPrincipal user,
                HttpContext httpContext,
                IAuthScopeContext scopeContext,
                IRequestDispatcher dispatcher,
                IOptions<AuthApplicationOptions> options,
                CancellationToken cancellationToken) =>
            {
                if (!this.TokenTenantMatches(user, scopeContext) ||
                    GetMemberId(user) is not { } memberId ||
                    GetSessionId(user) is not { } sessionId ||
                    !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
                {
                    return Results.Unauthorized();
                }

                return ToBrowserRefreshTokenBoundAuthResult(
                    await dispatcher.SendAsync(
                        new UnlinkExternalIdentityCommand(
                            memberId,
                            sessionId,
                            externalIdentityId,
                            request.CurrentPassword,
                            refreshToken),
                        cancellationToken).ConfigureAwait(false),
                    httpContext,
                    options.Value.RefreshTokenLifetimeDays);
            })
            .RequireAuthorization();
        unlinkIdentity.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(unlinkIdentity, requireScope);

        RouteHandlerBuilder activateTotp = browser.MapPost("/mfa/totp/activate", async (
            BrowserActivateTotpRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId ||
                !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
            {
                return Results.Unauthorized();
            }

            Result<RefreshTokenBoundCompletion<TotpActivationResponse>> result = await dispatcher.SendAsync(
                new ActivateTotpCommand(memberId, sessionId, request.Code, refreshToken),
                cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (result.Value.RefreshTokenReuseDetected)
            {
                DeleteBrowserCookies(httpContext);
                return ToRefreshTokenReuseHttpResult();
            }

            TotpActivationResponse response = result.Value.Response;
            SetBrowserCookies(
                httpContext,
                response.AccessToken,
                response.RefreshToken,
                options.Value.RefreshTokenLifetimeDays);
            return Results.Ok(new BrowserTotpActivationResponse(
                response.AccessToken,
                response.RecoveryCodes));
        })
            .RequireAuthorization();
        activateTotp.Produces<BrowserTotpActivationResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(activateTotp, requireScope);

        RouteHandlerBuilder completeMultiFactorChallenge = browser.MapPost("/mfa/challenges/complete", async (
            CompleteMultiFactorChallengeRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            Result<MultiFactorChallengeCompletion> result = await dispatcher.SendAsync(
                new CompleteMultiFactorChallengeCommand(
                    request.ChallengeToken,
                    request.CodeType,
                    request.Code),
                cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            return result.Value.Succeeded
                ? ToBrowserAuthResult(
                    Result.Success(result.Value.Tokens!),
                    httpContext,
                    options.Value.RefreshTokenLifetimeDays)
                : Results.Unauthorized();
        });
        completeMultiFactorChallenge.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        completeMultiFactorChallenge.Produces(StatusCodes.Status401Unauthorized);
        RequireScopeWhenNeeded(completeMultiFactorChallenge, requireScope);

        RouteHandlerBuilder regenerateRecoveryCodes = browser.MapPost("/mfa/recovery-codes/regenerate", async (
            BrowserVerifyMultiFactorCodeRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId ||
                !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
            {
                return Results.Unauthorized();
            }

            Result<MultiFactorRecoveryCodeRegenerationCompletion> result = await dispatcher.SendAsync(
                new RegenerateMultiFactorRecoveryCodesCommand(
                    memberId,
                    sessionId,
                    request.CodeType,
                    request.Code,
                    refreshToken),
                cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (!result.Value.Succeeded)
            {
                if (result.Value.RefreshTokenReuseDetected)
                {
                    DeleteBrowserCookies(httpContext);
                    return ToRefreshTokenReuseHttpResult();
                }

                return Results.Unauthorized();
            }

            MultiFactorRecoveryCodesResponse response = result.Value.Response!;

            SetBrowserCookies(
                httpContext,
                response.AccessToken,
                response.RefreshToken,
                options.Value.RefreshTokenLifetimeDays);
            return Results.Ok(new BrowserMultiFactorRecoveryCodesResponse(
                response.AccessToken,
                response.RecoveryCodes));
        })
            .RequireAuthorization();
        regenerateRecoveryCodes.Produces<BrowserMultiFactorRecoveryCodesResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(regenerateRecoveryCodes, requireScope);

        RouteHandlerBuilder disableTotp = browser.MapPost("/mfa/totp/disable", async (
            BrowserVerifyMultiFactorCodeRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId ||
                !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
            {
                return Results.Unauthorized();
            }

            Result<MultiFactorDisableCompletion> result = await dispatcher.SendAsync(
                new DisableTotpCommand(
                    memberId,
                    sessionId,
                    request.CodeType,
                    request.Code,
                    refreshToken),
                cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (!result.Value.Succeeded)
            {
                if (result.Value.RefreshTokenReuseDetected)
                {
                    DeleteBrowserCookies(httpContext);
                    return ToRefreshTokenReuseHttpResult();
                }

                return Results.Unauthorized();
            }

            DeleteBrowserCookies(httpContext);
            return Results.NoContent();
        })
            .RequireAuthorization();
        disableTotp.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(disableTotp, requireScope);

        RouteHandlerBuilder signOut = browser.MapPost("/sign-out", async (
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            try
            {
                if (!this.TokenTenantMatches(user, scopeContext) ||
                    GetMemberId(user) is not { } memberId ||
                    !TryGetBrowserCookie(httpContext, BrowserRefreshCookieName, out string? refreshToken))
                {
                    return Results.Unauthorized();
                }

                Result<Unit> result = await dispatcher.SendAsync(
                    new SignOutCommand(memberId, refreshToken),
                    cancellationToken).ConfigureAwait(false);

                return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
            }
            finally
            {
                DeleteBrowserCookies(httpContext);
            }
        })
            .RequireAuthorization();
        signOut.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(signOut, requireScope);

        RouteHandlerBuilder externalExchange = browser.MapPost("/external/exchange", async (
            ExternalAuthenticationExchangeRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            Result<ExternalAuthenticationResponse> result = await dispatcher.SendAsync(
                new ExchangeExternalAuthenticationCommand(
                    request.Code,
                    GetMemberId(user),
                    GetSessionId(user),
                    GetClientIpAddress(httpContext),
                    GetUserAgent(httpContext)),
                cancellationToken).ConfigureAwait(false);

            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (result.Value.Status == ExternalAuthenticationStatus.MultiFactorRequired)
            {
                SetNoStoreHeaders(httpContext);
                return Results.Accepted(value: result.Value.MultiFactorChallenge);
            }

            if (result.Value.Status != ExternalAuthenticationStatus.Authenticated)
            {
                return Results.Ok(result.Value);
            }

            httpContext.Response.Headers.CacheControl = "no-store";
            httpContext.Response.Headers.Pragma = "no-cache";
            httpContext.Response.Cookies.Append(
                BrowserRefreshCookieName,
                result.Value.RefreshToken!,
                CreateBrowserRefreshCookieOptions(httpContext, options.Value.RefreshTokenLifetimeDays));
            httpContext.Response.Cookies.Append(
                BrowserAccessCookieName,
                result.Value.AccessToken!,
                CreateBrowserRefreshCookieOptions(httpContext, options.Value.RefreshTokenLifetimeDays));

            return Results.Ok(new BrowserAuthResponse(result.Value.AccessToken!));
        });
        externalExchange.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        externalExchange.Produces<MultiFactorChallengeResponse>(StatusCodes.Status202Accepted);
        RequireScopeWhenNeeded(externalExchange, requireScope);
    }

}
