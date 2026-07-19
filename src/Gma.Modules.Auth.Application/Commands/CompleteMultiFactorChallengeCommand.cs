namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record CompleteMultiFactorChallengeCommand(
    string ChallengeToken,
    MultiFactorCodeType CodeType,
    string Code) : ITransactionalCommand<MultiFactorChallengeCompletion>;
