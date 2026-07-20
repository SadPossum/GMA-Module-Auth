namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record ActivateTotpCommand(
    Guid MemberId,
    Guid SessionId,
    string Code,
    string RefreshToken) : ITransactionalCommand<RefreshTokenBoundCompletion<TotpActivationResponse>>;
