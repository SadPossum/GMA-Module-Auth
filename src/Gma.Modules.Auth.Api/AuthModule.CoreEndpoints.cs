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
    private void MapCoreEndpoints(RouteGroupBuilder group, bool requireScope)
    {
        RouteHandlerBuilder selfRegistration = group.MapGet("/self-registration", (
            IOptions<AuthApplicationOptions> options) =>
            Results.Ok(new AuthSelfRegistrationResponse(
                options.Value.SelfRegistration.PasswordEnabled,
                options.Value.SelfRegistration.ExternalEnabled)));
        selfRegistration.Produces<AuthSelfRegistrationResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(selfRegistration, requireScope);

        RouteHandlerBuilder register = group.MapPost("/register", async (
            RegisterMemberRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
            ToSecretBearingHttpResult(
                await dispatcher.SendAsync(
                    new RegisterMemberCommand(
                        request.Username,
                        request.UsernameType,
                        request.Password),
                cancellationToken).ConfigureAwait(false),
                httpContext));
        register.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(register, requireScope);

        RouteHandlerBuilder login = group.MapPost("/login", async (
            LoginMemberRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
            ToPrimaryAuthenticationHttpResult(
                await dispatcher.SendAsync(
                    new LoginMemberCommand(
                        request.Username,
                        request.Password,
                        GetClientIpAddress(httpContext),
                        GetUserAgent(httpContext)),
                    cancellationToken).ConfigureAwait(false),
                httpContext));
        login.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        login.Produces<MultiFactorChallengeResponse>(StatusCodes.Status202Accepted);
        RequireScopeWhenNeeded(login, requireScope);

        RouteHandlerBuilder refresh = group.MapPost("/refresh", async (
            RefreshTokenRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
            ToRefreshTokenBoundHttpResult(
                await dispatcher.SendAsync(
                    new RefreshMemberSessionCommand(request.AccessToken, request.RefreshToken),
                cancellationToken).ConfigureAwait(false),
                httpContext));
        refresh.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(refresh, requireScope);

        RouteHandlerBuilder passwordStepUp = group.MapPost("/step-up/password", async (
            PasswordStepUpRequest request,
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

            return ToRefreshTokenBoundHttpResult(
                await dispatcher.SendAsync(
                    new StepUpWithPasswordCommand(
                        memberId,
                        sessionId,
                        request.Password,
                        request.RefreshToken),
                    cancellationToken).ConfigureAwait(false),
                httpContext);
        })
            .RequireAuthorization();
        passwordStepUp.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(passwordStepUp, requireScope);

        RouteHandlerBuilder externalExchange = group.MapPost("/external/exchange", async (
            ExternalAuthenticationExchangeRequest request,
            ClaimsPrincipal user,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
            ToExternalAuthenticationHttpResult(
                await dispatcher.SendAsync(
                    new ExchangeExternalAuthenticationCommand(
                        request.Code,
                        GetMemberId(user),
                        GetSessionId(user),
                        GetClientIpAddress(httpContext),
                        GetUserAgent(httpContext)),
                    cancellationToken).ConfigureAwait(false),
                httpContext));
        externalExchange.Produces<ExternalAuthenticationResponse>(StatusCodes.Status200OK);
        externalExchange.Produces<ExternalAuthenticationResponse>(StatusCodes.Status202Accepted);
        RequireScopeWhenNeeded(externalExchange, requireScope);

        RouteHandlerBuilder signOut = group.MapPost("/sign-out", async (
            SignOutRequest request,
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext))
            {
                return Results.Unauthorized();
            }

            Guid? memberId = GetMemberId(user);

            if (memberId is null)
            {
                return Results.Unauthorized();
            }

            Result<Unit> result = await dispatcher.SendAsync(
                new SignOutCommand(memberId.Value, request.RefreshToken),
                cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        signOut.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(signOut, requireScope);

        RouteHandlerBuilder signOutAll = group.MapPost("/sign-out-all", async (
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext))
            {
                return Results.Unauthorized();
            }

            Guid? memberId = GetMemberId(user);

            if (memberId is null)
            {
                return Results.Unauthorized();
            }

            Result<Unit> result = await dispatcher.SendAsync(
                new SignOutAllCommand(memberId.Value),
                cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        signOutAll.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(signOutAll, requireScope);

        RouteHandlerBuilder methods = group.MapGet("/methods", async (
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
                new GetAuthenticationMethodsQuery(memberId),
                cancellationToken).ConfigureAwait(false)).ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        methods.Produces<AuthenticationMethodsResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(methods, requireScope);

        RouteHandlerBuilder sessions = group.MapGet("/sessions", async (
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

            return (await dispatcher.QueryAsync(
                new ListAuthenticationSessionsQuery(memberId, sessionId),
                cancellationToken).ConfigureAwait(false)).ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        sessions.Produces<AuthenticationSessionsResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(sessions, requireScope);

        RouteHandlerBuilder signOutSession = group.MapPost("/sessions/{sessionId:guid}/sign-out", async (
            Guid sessionId,
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) || GetMemberId(user) is not { } memberId)
            {
                return Results.Unauthorized();
            }

            Result<Unit> result = await dispatcher.SendAsync(
                new SignOutSessionCommand(memberId, sessionId),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        signOutSession.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(signOutSession, requireScope);

        RouteHandlerBuilder setPassword = group.MapPut("/password", async (
            SetPasswordRequest request,
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

            return ToRefreshTokenBoundHttpResult(
                await dispatcher.SendAsync(
                    new SetMemberPasswordCommand(
                        memberId,
                        sessionId,
                        request.NewPassword,
                        request.CurrentPassword,
                        request.RefreshToken),
                    cancellationToken).ConfigureAwait(false),
                httpContext);
        })
            .RequireAuthorization();
        setPassword.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(setPassword, requireScope);

        RouteHandlerBuilder removePassword = group.MapPost("/password/remove", async (
            RemovePasswordRequest request,
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

            return ToRefreshTokenBoundHttpResult(
                await dispatcher.SendAsync(
                    new RemoveMemberPasswordCommand(
                        memberId,
                        sessionId,
                        request.CurrentPassword,
                        request.RefreshToken),
                    cancellationToken).ConfigureAwait(false),
                httpContext);
        })
            .RequireAuthorization();
        removePassword.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(removePassword, requireScope);

        RouteHandlerBuilder unlinkIdentity = group.MapPost("/external-identities/{externalIdentityId:guid}/unlink", async (
            Guid externalIdentityId,
            UnlinkExternalIdentityRequest request,
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

            return ToRefreshTokenBoundHttpResult(
                await dispatcher.SendAsync(
                    new UnlinkExternalIdentityCommand(
                        memberId,
                        sessionId,
                        externalIdentityId,
                        request.CurrentPassword,
                        request.RefreshToken),
                    cancellationToken).ConfigureAwait(false),
                httpContext);
        })
            .RequireAuthorization();
        unlinkIdentity.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(unlinkIdentity, requireScope);

        RouteHandlerBuilder requestPasswordRecovery = group.MapPost("/password-recovery", async (
            PasswordRecoveryRequest request,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            Result<Unit> result = await dispatcher.SendAsync(
                new RequestPasswordRecoveryCommand(request.Email),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.Accepted() : result.ToHttpResult(PublicErrorStatusCodes);
        });
        requestPasswordRecovery.Produces(StatusCodes.Status202Accepted);
        RequireScopeWhenNeeded(requestPasswordRecovery, requireScope);

        RouteHandlerBuilder confirmPasswordRecovery = group.MapPost("/password-recovery/confirm", async (
            ConfirmPasswordRecoveryRequest request,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            Result<Unit> result = await dispatcher.SendAsync(
                new ConfirmPasswordRecoveryCommand(request.Code, request.NewPassword),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        });
        confirmPasswordRecovery.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(confirmPasswordRecovery, requireScope);

        RouteHandlerBuilder requestEmailVerification = group.MapPost("/email-verification", async (
            RequestEmailVerificationRequest request,
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            if (!this.TokenTenantMatches(user, scopeContext) || GetMemberId(user) is not { } memberId)
            {
                return Results.Unauthorized();
            }

            Result<Unit> result = await dispatcher.SendAsync(
                new RequestEmailVerificationCommand(memberId, request.EmailId),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.Accepted() : result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        requestEmailVerification.Produces(StatusCodes.Status202Accepted);
        RequireScopeWhenNeeded(requestEmailVerification, requireScope);

        RouteHandlerBuilder confirmEmailVerification = group.MapPost("/email-verification/confirm", async (
            ConfirmEmailVerificationRequest request,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
        {
            Result<Unit> result = await dispatcher.SendAsync(
                new ConfirmEmailVerificationCommand(request.Code),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        });
        confirmEmailVerification.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(confirmEmailVerification, requireScope);

    }
}
