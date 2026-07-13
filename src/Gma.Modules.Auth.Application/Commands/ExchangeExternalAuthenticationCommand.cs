namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record ExchangeExternalAuthenticationCommand(
    string Code,
    Guid? CurrentMemberId,
    Guid? CurrentSessionId,
    string? IpAddress = null,
    string? UserAgent = null)
    : ITransactionalCommand<ExternalAuthenticationResponse>;
