namespace Gma.Modules.Auth.Application.ExternalAuthentication;

using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.Extensions.Options;

internal sealed class ExternalAuthenticationHandoffService(
    IExternalAuthenticationExchangeStore exchangeStore,
    ITokenService tokenService,
    IRefreshTokenHashingService tokenHashingService,
    ISystemClock clock,
    IIdGenerator idGenerator,
    IScopeContext scopeContext,
    IOptions<AuthApplicationOptions> options)
    : IExternalAuthenticationHandoffService
{
    public async Task<ExternalAuthenticationHandoff> CreateAsync(
        ValidatedExternalIdentity identity,
        ExternalAuthenticationIntent intent,
        string returnUrl,
        Guid? targetMemberId,
        Guid? targetSessionId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentException.ThrowIfNullOrWhiteSpace(returnUrl);

        string scopeId = scopeContext.ScopeId ?? throw new InvalidOperationException("A scope is required.");
        if (intent == ExternalAuthenticationIntent.Link &&
            (targetMemberId is null || targetSessionId is null))
        {
            throw new ArgumentException("Link handoffs require the target member and session.", nameof(intent));
        }

        string code = tokenService.GenerateRefreshToken();
        DateTimeOffset nowUtc = clock.UtcNow;
        DateTimeOffset expiresAtUtc = nowUtc.AddMinutes(options.Value.ExternalExchangeLifetimeMinutes);
        await exchangeStore.AddAsync(
            new ExternalAuthenticationExchange(
                idGenerator.NewId(),
                scopeId,
                tokenHashingService.HashRefreshToken(code),
                intent,
                identity.ProviderCode,
                identity.Issuer,
                identity.Subject,
                identity.Email,
                identity.EmailVerified,
                targetMemberId,
                targetSessionId,
                returnUrl.Trim(),
                nowUtc,
                expiresAtUtc),
            cancellationToken).ConfigureAwait(false);

        return new ExternalAuthenticationHandoff(code, returnUrl.Trim(), expiresAtUtc);
    }
}
