namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;

internal sealed class StepUpWithMultiFactorCommandValidator
    : ICommandValidator<StepUpWithMultiFactorCommand>
{
    public IEnumerable<string> Validate(StepUpWithMultiFactorCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
        }

        if (string.IsNullOrEmpty(command.Password))
        {
            yield return "Password is required.";
        }
        else if (command.Password.Length > AuthPasswordPolicy.MaximumLength)
        {
            yield return AuthPasswordPolicy.MaximumLengthMessage;
        }

        if (command.CodeType is MultiFactorCodeType.Unknown || !Enum.IsDefined(command.CodeType))
        {
            yield return "Multi-factor code type is invalid.";
        }

        if (string.IsNullOrWhiteSpace(command.Code))
        {
            yield return "Authentication code is required.";
        }
        else if (command.Code.Trim().Length > AuthContractLimits.AuthenticationCodeMaxLength)
        {
            yield return "Authentication code is too long.";
        }

        if (string.IsNullOrWhiteSpace(command.RefreshToken))
        {
            yield return "Refresh token is required.";
        }
        else if (command.RefreshToken.Trim().Length > AuthContractLimits.OpaqueTokenMaxLength)
        {
            yield return "Refresh token is too long.";
        }
    }
}
