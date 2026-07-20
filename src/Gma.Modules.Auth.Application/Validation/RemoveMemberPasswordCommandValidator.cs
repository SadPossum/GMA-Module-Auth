namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;

internal sealed class RemoveMemberPasswordCommandValidator : ICommandValidator<RemoveMemberPasswordCommand>
{
    public IEnumerable<string> Validate(RemoveMemberPasswordCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
        }

        if (string.IsNullOrWhiteSpace(command.CurrentPassword))
        {
            yield return "Current password is required.";
        }
        else if (command.CurrentPassword.Length > AuthPasswordPolicy.MaximumLength)
        {
            yield return "Current password is too long.";
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
