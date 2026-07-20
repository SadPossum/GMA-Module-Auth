namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;

internal sealed class StepUpWithPasswordCommandValidator : ICommandValidator<StepUpWithPasswordCommand>
{
    public IEnumerable<string> Validate(StepUpWithPasswordCommand command)
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
