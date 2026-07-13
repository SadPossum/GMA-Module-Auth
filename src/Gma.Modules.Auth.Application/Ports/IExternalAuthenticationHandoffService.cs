namespace Gma.Modules.Auth.Application.Ports;

using Gma.Modules.Auth.Application.ExternalAuthentication;

public interface IExternalAuthenticationHandoffService
{
    Task<ExternalAuthenticationHandoff> CreateAsync(
        ValidatedExternalIdentity identity,
        ExternalAuthenticationIntent intent,
        string returnUrl,
        Guid? targetMemberId,
        Guid? targetSessionId,
        CancellationToken cancellationToken);
}
