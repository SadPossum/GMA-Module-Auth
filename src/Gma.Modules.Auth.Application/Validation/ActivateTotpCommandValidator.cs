namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Contracts;

internal sealed class ActivateTotpCommandValidator : ICommandValidator<ActivateTotpCommand>
{
    public IEnumerable<string> Validate(ActivateTotpCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
        }

        if (string.IsNullOrWhiteSpace(command.Code))
        {
            yield return "TOTP code is required.";
        }
        else if (command.Code.Trim().Length > AuthContractLimits.AuthenticationCodeMaxLength)
        {
            yield return "TOTP code is too long.";
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
