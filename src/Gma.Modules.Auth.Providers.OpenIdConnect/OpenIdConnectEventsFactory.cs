namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using System.Globalization;
using System.Security.Claims;
using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Security;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Ports;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

internal static class OpenIdConnectEventsFactory
{
    public static OpenIdConnectEvents Create(AuthOpenIdConnectProviderOptions providerOptions) =>
        new()
        {
            OnTokenValidated = context => HandleTokenValidatedAsync(context, providerOptions),
            OnTicketReceived = HandleTicketReceivedAsync,
            OnRemoteFailure = HandleRemoteFailureAsync,
        };

    private static async Task HandleTokenValidatedAsync(
        TokenValidatedContext context,
        AuthOpenIdConnectProviderOptions providerOptions)
    {
        SetNoStoreHeaders(context.Response);
        if (!OpenIdConnectHandoffScope.TryRestore(
                context.Properties,
                context.HttpContext.RequestServices))
        {
            context.Fail("The external authentication handoff is missing a valid scope.");
            return;
        }

        string? provider = GetItem(context.Properties, OpenIdConnectHandoffProperties.Provider);
        string? returnUrl = GetItem(context.Properties, OpenIdConnectHandoffProperties.ReturnUrl);
        string? intentValue = GetItem(context.Properties, OpenIdConnectHandoffProperties.Intent);
        string? issuer = context.SecurityToken.Issuer;
        string? subject = context.Principal?.FindFirstValue(ApplicationClaimNames.Subject);
        string? email = context.Principal?.FindFirstValue(providerOptions.EmailClaim);
        bool emailVerified = !string.IsNullOrWhiteSpace(email) &&
            (providerOptions.TreatEmailAsVerified ||
             (bool.TryParse(
                 context.Principal?.FindFirstValue(providerOptions.EmailVerifiedClaim),
                 out bool parsedEmailVerified) && parsedEmailVerified));

        if (string.IsNullOrWhiteSpace(provider) ||
            string.IsNullOrWhiteSpace(returnUrl) ||
            string.IsNullOrWhiteSpace(issuer) ||
            string.IsNullOrWhiteSpace(subject) ||
            !Enum.TryParse(intentValue, ignoreCase: true, out ExternalAuthenticationIntent intent))
        {
            context.Fail("The validated identity is missing required OpenID Connect claims or handoff state.");
            return;
        }

        Guid? targetMemberId = ParseOptionalGuid(
            GetItem(context.Properties, OpenIdConnectHandoffProperties.TargetMemberId));
        Guid? targetSessionId = ParseOptionalGuid(
            GetItem(context.Properties, OpenIdConnectHandoffProperties.TargetSessionId));
        ValidatedExternalIdentity identity;
        try
        {
            identity = new ValidatedExternalIdentity(provider, issuer, subject, email, emailVerified);
        }
        catch (ArgumentException exception)
        {
            context.Fail(exception);
            return;
        }

        IRequestDispatcher dispatcher = context.HttpContext.RequestServices.GetRequiredService<IRequestDispatcher>();
        Result<ExternalAuthenticationHandoff> result = await dispatcher.SendAsync(
            new CreateExternalAuthenticationHandoffCommand(
                identity,
                intent,
                returnUrl,
                targetMemberId,
                targetSessionId),
            context.HttpContext.RequestAborted).ConfigureAwait(false);
        if (result.IsFailure)
        {
            context.Fail(result.Error.Message);
            return;
        }

        context.Properties!.Items[OpenIdConnectHandoffProperties.ExchangeCode] = result.Value.Code;
    }

    private static Task HandleTicketReceivedAsync(TicketReceivedContext context)
    {
        string? returnUrl = GetItem(context.Properties, OpenIdConnectHandoffProperties.ReturnUrl);
        string? provider = GetItem(context.Properties, OpenIdConnectHandoffProperties.Provider);
        string? exchangeCode = GetItem(context.Properties, OpenIdConnectHandoffProperties.ExchangeCode);
        if (string.IsNullOrWhiteSpace(returnUrl) ||
            string.IsNullOrWhiteSpace(provider) ||
            string.IsNullOrWhiteSpace(exchangeCode))
        {
            context.Fail("External authentication handoff was not created.");
            return Task.CompletedTask;
        }

        string destination = QueryHelpers.AddQueryString(returnUrl, new Dictionary<string, string?>
        {
            ["code"] = exchangeCode,
            ["provider"] = provider,
        });
        SetNoStoreHeaders(context.Response);
        context.Response.Redirect(destination);
        context.HandleResponse();
        return Task.CompletedTask;
    }

    private static Task HandleRemoteFailureAsync(RemoteFailureContext context)
    {
        SetNoStoreHeaders(context.Response);
        string? returnUrl = GetItem(context.Properties, OpenIdConnectHandoffProperties.ReturnUrl);
        if (!string.IsNullOrWhiteSpace(returnUrl))
        {
            string destination = QueryHelpers.AddQueryString(
                returnUrl,
                "error",
                "external_authentication_failed");
            context.Response.Redirect(destination);
            context.HandleResponse();
        }

        return Task.CompletedTask;
    }

    private static void SetNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
    }

    private static string? GetItem(
        AuthenticationProperties? properties,
        string key) =>
        properties?.Items.TryGetValue(key, out string? value) == true ? value : null;

    private static Guid? ParseOptionalGuid(string? value) =>
        Guid.TryParse(value, CultureInfo.InvariantCulture, out Guid parsed) ? parsed : null;
}
