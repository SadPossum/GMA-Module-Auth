namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record StepUpWithMultiFactorCommand(
    Guid MemberId,
    Guid SessionId,
    string Password,
    MultiFactorCodeType CodeType,
    string Code,
    string RefreshToken) : ITransactionalCommand<MultiFactorStepUpCompletion>;
