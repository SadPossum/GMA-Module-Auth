namespace Gma.Modules.Auth.Infrastructure.JwtBearer;

using System.Security.Claims;
using Gma.Framework.Naming;
using Gma.Framework.Security;
using Gma.Modules.Auth.Contracts;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed class AuthBearerAdmissionPostConfigureOptions(
    IOptions<AuthBearerAdmissionOptions> admissionOptions,
    IServiceProviderIsService serviceProviderIsService)
    : IPostConfigureOptions<JwtBearerOptions>
{
    private const string AdmissionFailure = "The authentication session is no longer active.";

    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!string.Equals(name, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return;
        }

        AuthBearerAdmissionMode mode = admissionOptions.Value.Mode;
        if (mode == AuthBearerAdmissionMode.TokenLifetime)
        {
            return;
        }

        if (mode != AuthBearerAdmissionMode.ActiveSession)
        {
            throw CreateOptionsException("Mode is invalid.");
        }

        if (!serviceProviderIsService.IsService(typeof(IAuthSessionAdmissionReader)))
        {
            throw CreateOptionsException(
                $"{nameof(IAuthSessionAdmissionReader)} must be registered for ActiveSession mode.");
        }

        if (options.EventsType is not null)
        {
            throw CreateOptionsException(
                "JwtBearerOptions.EventsType cannot be used with ActiveSession mode; configure JwtBearerOptions.Events so admission can compose with existing handlers.");
        }

        Func<TokenValidatedContext, Task> existingHandler = options.Events.OnTokenValidated;
        options.Events.OnTokenValidated = async context =>
        {
            await existingHandler(context).ConfigureAwait(false);
            if (context.Result is not null || context.Principal is null)
            {
                return;
            }

            ClaimsPrincipal principal = context.Principal;
            string? scopeId = principal.FindFirstValue(ApplicationClaimNames.ScopeId);
            if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) ||
                !Guid.TryParse(principal.FindFirstValue(ApplicationClaimNames.Subject), out Guid memberId) ||
                memberId == Guid.Empty ||
                !Guid.TryParse(principal.FindFirstValue(ApplicationClaimNames.SessionId), out Guid sessionId) ||
                sessionId == Guid.Empty)
            {
                context.Fail(AdmissionFailure);
                return;
            }

            IAuthSessionAdmissionReader reader = context.HttpContext.RequestServices
                .GetRequiredService<IAuthSessionAdmissionReader>();
            bool isActive = await reader.IsActiveAsync(
                    normalizedScopeId,
                    memberId,
                    sessionId,
                    context.HttpContext.RequestAborted)
                .ConfigureAwait(false);

            if (!isActive)
            {
                context.Fail(AdmissionFailure);
            }
        };
    }

    private static OptionsValidationException CreateOptionsException(string failure) =>
        new(
            AuthBearerAdmissionOptions.SectionName,
            typeof(AuthBearerAdmissionOptions),
            [$"{AuthBearerAdmissionOptions.SectionName}:{failure}"]);
}
