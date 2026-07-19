namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record DisableTotpCommand(
    Guid MemberId,
    Guid SessionId,
    MultiFactorCodeType CodeType,
    string Code,
    string RefreshToken) : ITransactionalCommand<MultiFactorDisableCompletion>;
