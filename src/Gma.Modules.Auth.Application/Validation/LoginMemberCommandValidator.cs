namespace Gma.Modules.Auth.Application.Validation;

using Gma.Modules.Auth.Application.Commands;
using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;

internal sealed class LoginMemberCommandValidator : ICommandValidator<LoginMemberCommand>
{
    public IEnumerable<string> Validate(LoginMemberCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Username))
        {
            yield return "Username is required.";
        }
        else if (command.Username.Trim().Length > AuthContractLimits.UsernameMaxLength)
        {
            yield return "Username is too long.";
        }

        if (string.IsNullOrWhiteSpace(command.Password))
        {
            yield return "Password is required.";
        }
        else if (command.Password.Length > AuthPasswordPolicy.MaximumLength)
        {
            yield return AuthPasswordPolicy.MaximumLengthMessage;
        }
    }
}
