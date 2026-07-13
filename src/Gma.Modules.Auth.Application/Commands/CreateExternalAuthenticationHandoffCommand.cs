namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Ports;

public sealed record CreateExternalAuthenticationHandoffCommand(
    ValidatedExternalIdentity Identity,
    ExternalAuthenticationIntent Intent,
    string ReturnUrl,
    Guid? TargetMemberId,
    Guid? TargetSessionId)
    : ITransactionalCommand<ExternalAuthenticationHandoff>;
