namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using System.Security.Claims;
using Gma.Framework.Api.Scoping;
using Gma.Framework.Security;
using Gma.Modules.Auth.Api;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

internal sealed class OpenIdConnectAuthEndpointContributor(
    OpenIdConnectProviderRegistry providers,
    ExternalReturnUrlPolicy returnUrlPolicy,
    ExternalAuthenticationChallengeHandoff handoff)
    : IAuthEndpointContributor
{
    public void MapEndpoints(RouteGroupBuilder authGroup, AuthProfile profile)
    {
        RouteHandlerBuilder providerList = authGroup.MapGet("/external/providers", () =>
            Results.Ok(new ExternalAuthenticationProviderListResponse(providers.ProviderCodes)));
        providerList.Produces<ExternalAuthenticationProviderListResponse>(StatusCodes.Status200OK);

        RouteHandlerBuilder browserSignIn = authGroup.MapPost("/external/{provider}/sign-in/challenge", (
            string provider,
            ExternalAuthenticationChallengeRequest request,
            HttpContext httpContext,
            IAuthScopeContext scopeContext) =>
            this.CreateBrowserHandoff(
                httpContext,
                provider,
                request.ReturnUrl,
                scopeContext.ScopeId,
                ExternalAuthenticationIntent.SignIn,
                targetMemberId: null,
                targetSessionId: null));
        browserSignIn.Produces<ExternalAuthenticationChallengeResponse>(StatusCodes.Status200OK);
        ApplyScope(browserSignIn, profile);

        RouteHandlerBuilder browserLink = authGroup.MapPost("/external/{provider}/link/challenge", (
            string provider,
            ExternalAuthenticationChallengeRequest request,
            HttpContext httpContext,
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext) =>
        {
            if (!TokenScopeMatches(profile, user, scopeContext) ||
                !TryGetClaimGuid(user, ClaimTypes.NameIdentifier, out Guid memberId) ||
                !TryGetClaimGuid(user, ApplicationClaimNames.SessionId, out Guid sessionId))
            {
                return Results.Unauthorized();
            }

            return this.CreateBrowserHandoff(
                httpContext,
                provider,
                request.ReturnUrl,
                scopeContext.ScopeId,
                ExternalAuthenticationIntent.Link,
                memberId,
                sessionId);
        })
            .RequireAuthorization();
        browserLink.Produces<ExternalAuthenticationChallengeResponse>(StatusCodes.Status200OK);
        ApplyScope(browserLink, profile);

        RouteHandlerBuilder browserChallenge = authGroup.MapGet("/external/challenge/{nonce}", (
            string nonce,
            HttpContext httpContext,
            IAuthScopeContext scopeContext) =>
        {
            if (!handoff.TryConsume(httpContext, nonce, out ExternalAuthenticationChallengeHandoff.ChallengePayload? payload) ||
                payload is null)
            {
                return Results.BadRequest(new { error = "The external authentication challenge is missing or expired." });
            }

            if (!scopeContext.TryRestoreScope(payload.ScopeId))
            {
                return Results.BadRequest(new { error = "The external authentication challenge scope is invalid." });
            }

            return this.CreateChallenge(
                payload.ProviderKey,
                payload.ReturnUrl,
                payload.ScopeId,
                payload.Intent,
                payload.TargetMemberId,
                payload.TargetSessionId);
        });
        browserChallenge.ExcludeFromDescription();

        RouteHandlerBuilder signIn = authGroup.MapGet("/external/{provider}/sign-in", (
            string provider,
            string returnUrl,
            IAuthScopeContext scopeContext) =>
            this.CreateChallenge(
                provider,
                returnUrl,
                scopeContext.ScopeId,
                ExternalAuthenticationIntent.SignIn,
                targetMemberId: null,
                targetSessionId: null));
        ApplyScope(signIn, profile);

        RouteHandlerBuilder link = authGroup.MapGet("/external/{provider}/link", (
            string provider,
            string returnUrl,
            ClaimsPrincipal user,
            IAuthScopeContext scopeContext) =>
        {
            if (!TokenScopeMatches(profile, user, scopeContext) ||
                !TryGetClaimGuid(user, ClaimTypes.NameIdentifier, out Guid memberId) ||
                !TryGetClaimGuid(user, ApplicationClaimNames.SessionId, out Guid sessionId))
            {
                return Results.Unauthorized();
            }

            return this.CreateChallenge(
                provider,
                returnUrl,
                scopeContext.ScopeId,
                ExternalAuthenticationIntent.Link,
                memberId,
                sessionId);
        })
            .RequireAuthorization();
        ApplyScope(link, profile);
    }

    private IResult CreateBrowserHandoff(
        HttpContext httpContext,
        string provider,
        string returnUrl,
        string? scopeId,
        ExternalAuthenticationIntent intent,
        Guid? targetMemberId,
        Guid? targetSessionId)
    {
        if (!providers.TryGetScheme(provider, out _))
        {
            return Results.NotFound();
        }

        if (!returnUrlPolicy.TryValidate(returnUrl, out string validatedReturnUrl))
        {
            return Results.BadRequest(new { error = "The external authentication return URL is not allowed." });
        }

        return Results.Ok(handoff.Issue(
            httpContext,
            provider,
            validatedReturnUrl,
            scopeId,
            intent,
            targetMemberId,
            targetSessionId));
    }

    private IResult CreateChallenge(
        string provider,
        string returnUrl,
        string? scopeId,
        ExternalAuthenticationIntent intent,
        Guid? targetMemberId,
        Guid? targetSessionId)
    {
        if (!providers.TryGetScheme(provider, out string scheme))
        {
            return Results.NotFound();
        }

        if (!returnUrlPolicy.TryValidate(returnUrl, out string validatedReturnUrl))
        {
            return Results.BadRequest(new { error = "The external authentication return URL is not allowed." });
        }

        AuthenticationProperties properties = new()
        {
            RedirectUri = validatedReturnUrl,
        };
        properties.Items[OpenIdConnectHandoffProperties.Provider] =
            OpenIdConnectProviderRegistry.NormalizeProviderKey(provider);
        properties.Items[OpenIdConnectHandoffProperties.Intent] = intent.ToString();
        properties.Items[OpenIdConnectHandoffProperties.ReturnUrl] = validatedReturnUrl;
        OpenIdConnectHandoffScope.Store(properties, scopeId);
        if (targetMemberId is not null)
        {
            properties.Items[OpenIdConnectHandoffProperties.TargetMemberId] = targetMemberId.Value.ToString("D");
        }

        if (targetSessionId is not null)
        {
            properties.Items[OpenIdConnectHandoffProperties.TargetSessionId] = targetSessionId.Value.ToString("D");
        }

        if (intent == ExternalAuthenticationIntent.Link)
        {
            properties.Parameters["prompt"] = "select_account";
        }

        return Results.Challenge(properties, [scheme]);
    }

    private static void ApplyScope(RouteHandlerBuilder endpoint, AuthProfile profile)
    {
        if (profile.RequiresScopeContext)
        {
            endpoint.RequireScope();
        }
    }

    private static bool TokenScopeMatches(AuthProfile profile, ClaimsPrincipal user, IAuthScopeContext scopeContext) =>
        !profile.RequiresScopeContext ||
        !scopeContext.IsEnabled ||
        string.Equals(
            user.FindFirstValue(ApplicationClaimNames.ScopeId),
            scopeContext.ScopeId,
            StringComparison.Ordinal);

    private static bool TryGetClaimGuid(
        ClaimsPrincipal user,
        string claimType,
        out Guid value) =>
        Guid.TryParse(user.FindFirstValue(claimType), out value);
}
