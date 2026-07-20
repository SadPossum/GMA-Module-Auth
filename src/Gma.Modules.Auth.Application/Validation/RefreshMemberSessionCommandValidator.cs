namespace Gma.Modules.Auth.Application.Validation;

using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Contracts;
using Gma.Framework.Cqrs;

internal sealed class RefreshMemberSessionCommandValidator : ICommandValidator<RefreshMemberSessionCommand>
{
    public IEnumerable<string> Validate(RefreshMemberSessionCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.AccessToken))
        {
            yield return "Access token is required.";
        }
        else if (command.AccessToken.Trim().Length > AuthContractLimits.AccessTokenMaxLength)
        {
            yield return "Access token is too long.";
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
