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
    private void MapMultiFactorEndpoints(RouteGroupBuilder group, bool requireScope)
    {
        RouteHandlerBuilder multiFactorStepUp = group.MapPost("/step-up/mfa", async (
            MultiFactorStepUpRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId)
            {
                return Results.Unauthorized();
            }

            Result<MultiFactorStepUpCompletion> result = await dispatcher.SendAsync(
                new StepUpWithMultiFactorCommand(
                    memberId,
                    sessionId,
                    request.Password,
                    request.CodeType,
                    request.Code,
                    request.RefreshToken),
                cancellationToken).ConfigureAwait(false);
            return ToMultiFactorStepUpHttpResult(result, httpContext);
        })
            .RequireAuthorization();
        multiFactorStepUp.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        multiFactorStepUp.Produces(StatusCodes.Status401Unauthorized);
        RequireScopeWhenNeeded(multiFactorStepUp, requireScope);

        RouteHandlerBuilder multiFactorStatus = group.MapGet("/mfa", async (
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) || GetMemberId(user) is not { } memberId)
            {
                return Results.Unauthorized();
            }

            return (await dispatcher.QueryAsync(
                new GetMultiFactorStatusQuery(memberId),
                cancellationToken).ConfigureAwait(false)).ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        multiFactorStatus.Produces<MultiFactorStatusResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(multiFactorStatus, requireScope);

        RouteHandlerBuilder beginTotpEnrollment = group.MapPost("/mfa/totp/enrollment", async (
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId)
            {
                return Results.Unauthorized();
            }

            Result<TotpEnrollmentResponse> result = await dispatcher.SendAsync(
                new BeginTotpEnrollmentCommand(memberId, sessionId),
                cancellationToken).ConfigureAwait(false);
            SetNoStoreHeaders(httpContext);
            return result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        beginTotpEnrollment.Produces<TotpEnrollmentResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(beginTotpEnrollment, requireScope);

        RouteHandlerBuilder activateTotp = group.MapPost("/mfa/totp/activate", async (
            ActivateTotpRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId)
            {
                return Results.Unauthorized();
            }

            Result<RefreshTokenBoundCompletion<TotpActivationResponse>> result = await dispatcher.SendAsync(
                new ActivateTotpCommand(memberId, sessionId, request.Code, request.RefreshToken),
                cancellationToken).ConfigureAwait(false);
            return ToRefreshTokenBoundHttpResult(result, httpContext);
        })
            .RequireAuthorization();
        activateTotp.Produces<TotpActivationResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(activateTotp, requireScope);

        RouteHandlerBuilder completeMultiFactorChallenge = group.MapPost("/mfa/challenges/complete", async (
            CompleteMultiFactorChallengeRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            Result<MultiFactorChallengeCompletion> result = await dispatcher.SendAsync(
                new CompleteMultiFactorChallengeCommand(
                    request.ChallengeToken,
                    request.CodeType,
                    request.Code),
                cancellationToken).ConfigureAwait(false);
            SetNoStoreHeaders(httpContext);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            return result.Value.Succeeded
                ? Results.Ok(result.Value.Tokens)
                : Results.Unauthorized();
        });
        completeMultiFactorChallenge.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        completeMultiFactorChallenge.Produces(StatusCodes.Status401Unauthorized);
        RequireScopeWhenNeeded(completeMultiFactorChallenge, requireScope);

        RouteHandlerBuilder regenerateRecoveryCodes = group.MapPost("/mfa/recovery-codes/regenerate", async (
            VerifyMultiFactorCodeRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId)
            {
                return Results.Unauthorized();
            }

            Result<MultiFactorRecoveryCodeRegenerationCompletion> result = await dispatcher.SendAsync(
                new RegenerateMultiFactorRecoveryCodesCommand(
                    memberId,
                    sessionId,
                    request.CodeType,
                    request.Code,
                    request.RefreshToken),
                cancellationToken).ConfigureAwait(false);
            SetNoStoreHeaders(httpContext);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (result.Value.RefreshTokenReuseDetected)
            {
                return ToRefreshTokenReuseHttpResult();
            }

            return result.Value.Succeeded
                ? Results.Ok(result.Value.Response)
                : Results.Unauthorized();
        })
            .RequireAuthorization();
        regenerateRecoveryCodes.Produces<MultiFactorRecoveryCodesResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(regenerateRecoveryCodes, requireScope);

        RouteHandlerBuilder disableTotp = group.MapPost("/mfa/totp/disable", async (
            VerifyMultiFactorCodeRequest request,
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) ||
                GetMemberId(user) is not { } memberId ||
                GetSessionId(user) is not { } sessionId)
            {
                return Results.Unauthorized();
            }

            Result<MultiFactorDisableCompletion> result = await dispatcher.SendAsync(
                new DisableTotpCommand(
                    memberId,
                    sessionId,
                    request.CodeType,
                    request.Code,
                    request.RefreshToken),
                cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            if (result.Value.RefreshTokenReuseDetected)
            {
                return ToRefreshTokenReuseHttpResult();
            }

            return result.Value.Succeeded ? Results.NoContent() : Results.Unauthorized();
        })
            .RequireAuthorization();
        disableTotp.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(disableTotp, requireScope);

    }
}
