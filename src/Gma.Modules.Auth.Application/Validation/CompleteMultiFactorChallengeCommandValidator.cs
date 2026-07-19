namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Contracts;

internal sealed class CompleteMultiFactorChallengeCommandValidator
    : ICommandValidator<CompleteMultiFactorChallengeCommand>
{
    public IEnumerable<string> Validate(CompleteMultiFactorChallengeCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.ChallengeToken))
        {
            yield return "Challenge token is required.";
        }

        if (command.CodeType is MultiFactorCodeType.Unknown || !Enum.IsDefined(command.CodeType))
        {
            yield return "Multi-factor code type is invalid.";
        }

        if (string.IsNullOrWhiteSpace(command.Code))
        {
            yield return "Authentication code is required.";
        }
    }
}
