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

public sealed class AuthModule(AuthProfile profile) : IModule
{
    private const string BrowserAccessCookieName = "gma.auth.access";
    private const string BrowserRefreshCookieName = "gma.auth.refresh";
    private const string BrowserRefreshCookiePath = "/api/auth/browser";
    private readonly AuthProfile profile = profile ?? throw new ArgumentNullException(nameof(profile));

    public AuthModule()
        : this(AuthProfile.ScopeAware())
    {
    }

    public string Name => AuthModuleMetadata.Name;

    public void AddServices(IHostApplicationBuilder builder)
    {
        AddProfileServices(builder, this.profile);
        builder.Services.AddAuthApplication(builder.Configuration, this.profile);
        builder.Services.AddAuthInfrastructure(builder.Configuration);
        builder
            .AddAuthJwtBearerAuthentication()
            .AddAuthPersistence(this.profile);
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints)
    {
        bool requireScope = this.profile.RequiresScopeContext;
        RouteGroupBuilder group = endpoints.MapGroup("/api/auth")
            .WithModuleName(this.Name)
            .WithTags("Auth");

        RouteHandlerBuilder selfRegistration = group.MapGet("/self-registration", (
            IOptions<AuthApplicationOptions> options) =>
            Results.Ok(new AuthSelfRegistrationResponse(
                options.Value.SelfRegistration.PasswordEnabled,
                options.Value.SelfRegistration.ExternalEnabled)));
        selfRegistration.Produces<AuthSelfRegistrationResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(selfRegistration, requireScope);

        RouteHandlerBuilder register = group.MapPost("/register", async (
            RegisterMemberApiRequest request,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
            (await dispatcher.SendAsync(
                new RegisterMemberCommand(
                    request.Username,
                    UsernameTypeInput.FromJsonElement(request.UsernameType).Value,
                    request.Password),
                cancellationToken).ConfigureAwait(false)).ToHttpResult(PublicErrorStatusCodes));
        RequireScopeWhenNeeded(register, requireScope);

        RouteHandlerBuilder login = group.MapPost("/login", async (
            LoginMemberRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
            ToPrimaryAuthenticationHttpResult(await dispatcher.SendAsync(
                new LoginMemberCommand(
                    request.Username,
                    request.Password,
                    GetClientIpAddress(httpContext),
                    GetUserAgent(httpContext)),
                cancellationToken).ConfigureAwait(false)));
        login.Produces<AuthTokensResponse>(StatusCodes.Status200OK);
        login.Produces<MultiFactorChallengeResponse>(StatusCodes.Status202Accepted);
        RequireScopeWhenNeeded(login, requireScope);

        RouteHandlerBuilder refresh = group.MapPost("/refresh", async (
            RefreshTokenRequest request,
            IRequestDispatcher dispatcher,
            CancellationToken cancellationToken) =>
            (await dispatcher.SendAsync(
                new RefreshMemberSessionCommand(request.AccessToken, request.RefreshToken),
                cancellationToken).ConfigureAwait(false)).ToHttpResult(PublicErrorStatusCodes));
        RequireScopeWhenNeeded(refresh, requireScope);

        RouteHandlerBuilder passwordStepUp = group.MapPost("/step-up/password", async (
            PasswordStepUpRequest request,
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

            return (await dispatcher.SendAsync(
                new StepUpWithPasswordCommand(
                    memberId,
                    sessionId,
                    request.Password,
                    request.RefreshToken),
                cancellationToken).ConfigureAwait(false)).ToHttpResult(PublicErrorStatusCodes);
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
        RequireScopeWhenNeeded(signOutSession, requireScope);

        RouteHandlerBuilder setPassword = group.MapPut("/password", async (
            SetPasswordRequest request,
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

            Result<Unit> result = await dispatcher.SendAsync(
                new SetMemberPasswordCommand(
                    memberId,
                    sessionId,
                    request.NewPassword,
                    request.CurrentPassword),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        RequireScopeWhenNeeded(setPassword, requireScope);

        RouteHandlerBuilder removePassword = group.MapPost("/password/remove", async (
            RemovePasswordRequest request,
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

            Result<Unit> result = await dispatcher.SendAsync(
                new RemoveMemberPasswordCommand(memberId, sessionId, request.CurrentPassword),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
        RequireScopeWhenNeeded(removePassword, requireScope);

        RouteHandlerBuilder unlinkIdentity = group.MapPost("/external-identities/{externalIdentityId:guid}/unlink", async (
            Guid externalIdentityId,
            UnlinkExternalIdentityRequest request,
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

            Result<Unit> result = await dispatcher.SendAsync(
                new UnlinkExternalIdentityCommand(
                    memberId,
                    sessionId,
                    externalIdentityId,
                    request.CurrentPassword),
                cancellationToken).ConfigureAwait(false);
            return result.IsSuccess ? Results.NoContent() : result.ToHttpResult(PublicErrorStatusCodes);
        })
            .RequireAuthorization();
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
        RequireScopeWhenNeeded(confirmEmailVerification, requireScope);

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

            Result<TotpActivationResponse> result = await dispatcher.SendAsync(
                new ActivateTotpCommand(memberId, sessionId, request.Code, request.RefreshToken),
                cancellationToken).ConfigureAwait(false);
            SetNoStoreHeaders(httpContext);
            return result.ToHttpResult(PublicErrorStatusCodes);
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

            return result.Value.Succeeded ? Results.NoContent() : Results.Unauthorized();
        })
            .RequireAuthorization();
        disableTotp.Produces(StatusCodes.Status204NoContent);
        RequireScopeWhenNeeded(disableTotp, requireScope);

        this.MapBrowserEndpoints(group, requireScope);

        foreach (IAuthEndpointContributor contributor in endpoints.ServiceProvider.GetServices<IAuthEndpointContributor>())
        {
            contributor.MapEndpoints(group, this.profile);
        }
    }

    private void MapBrowserEndpoints(RouteGroupBuilder authGroup, bool requireScope)
    {
        RouteGroupBuilder browser = authGroup.MapGroup("/browser");

        RouteHandlerBuilder register = browser.MapPost("/register", async (
            RegisterMemberApiRequest request,
            HttpContext httpContext,
            IRequestDispatcher dispatcher,
            IOptions<AuthApplicationOptions> options,
            CancellationToken cancellationToken) =>
        {
            Result<AuthTokensResponse> result = await dispatcher.SendAsync(
                new RegisterMemberCommand(
                    request.Username,
                    UsernameTypeInput.FromJsonElement(request.UsernameType).Value,
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

            Result<AuthTokensResponse> result = await dispatcher.SendAsync(
                new RefreshMemberSessionCommand(accessToken, refreshToken),
                cancellationToken).ConfigureAwait(false);

            if (result.IsFailure)
            {
                DeleteBrowserCookies(httpContext);
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            return ToBrowserAuthResult(result, httpContext, options.Value.RefreshTokenLifetimeDays);
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

            Result<AuthTokensResponse> result = await dispatcher.SendAsync(
                new StepUpWithPasswordCommand(memberId, sessionId, request.Password, refreshToken),
                cancellationToken).ConfigureAwait(false);
            return ToBrowserAuthResult(result, httpContext, options.Value.RefreshTokenLifetimeDays);
        })
            .RequireAuthorization();
        passwordStepUp.Produces<BrowserAuthResponse>(StatusCodes.Status200OK);
        RequireScopeWhenNeeded(passwordStepUp, requireScope);

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

            Result<TotpActivationResponse> result = await dispatcher.SendAsync(
                new ActivateTotpCommand(memberId, sessionId, request.Code, refreshToken),
                cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
            {
                return result.ToHttpResult(PublicErrorStatusCodes);
            }

            SetBrowserCookies(
                httpContext,
                result.Value.AccessToken,
                result.Value.RefreshToken,
                options.Value.RefreshTokenLifetimeDays);
            return Results.Ok(new BrowserTotpActivationResponse(
                result.Value.AccessToken,
                result.Value.RecoveryCodes));
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

    private static IResult ToPrimaryAuthenticationHttpResult(Result<PrimaryAuthenticationResult> result)
    {
        if (result.IsFailure)
        {
            return result.ToHttpResult(PublicErrorStatusCodes);
        }

        return result.Value.RequiresMultiFactor
            ? Results.Accepted(value: result.Value.MultiFactorChallenge)
            : Results.Ok(result.Value.Tokens);
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

public static class AuthModuleHostBuilderExtensions
{
    public static IHostApplicationBuilder AddAuthModule(this IHostApplicationBuilder builder, AuthProfile profile)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(profile);

        return builder.AddModule(new AuthModule(profile));
    }
}
