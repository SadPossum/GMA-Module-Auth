namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;

internal sealed class ConfirmPasswordRecoveryCommandValidator : ICommandValidator<ConfirmPasswordRecoveryCommand>
{
    public IEnumerable<string> Validate(ConfirmPasswordRecoveryCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Code))
        {
            yield return "Password recovery code is required.";
        }
        else if (command.Code.Trim().Length > 2_048)
        {
            yield return "Password recovery code is too long.";
        }

        if (string.IsNullOrEmpty(command.NewPassword) || command.NewPassword.Length < AuthPasswordPolicy.MinimumLength)
        {
            yield return AuthPasswordPolicy.MinimumLengthMessage;
        }

        if (command.NewPassword?.Length > AuthPasswordPolicy.MaximumLength)
        {
            yield return AuthPasswordPolicy.MaximumLengthMessage;
        }
    }
}
