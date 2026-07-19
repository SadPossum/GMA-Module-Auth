namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Contracts;

internal sealed class RegenerateMultiFactorRecoveryCodesCommandValidator
    : ICommandValidator<RegenerateMultiFactorRecoveryCodesCommand>
{
    public IEnumerable<string> Validate(RegenerateMultiFactorRecoveryCodesCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
        }

        if (command.CodeType is MultiFactorCodeType.Unknown || !Enum.IsDefined(command.CodeType))
        {
            yield return "Multi-factor code type is invalid.";
        }

        if (string.IsNullOrWhiteSpace(command.Code))
        {
            yield return "Authentication code is required.";
        }

        if (string.IsNullOrWhiteSpace(command.RefreshToken))
        {
            yield return "Refresh token is required.";
        }
    }
}
