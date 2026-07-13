namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

internal sealed class ConfirmEmailVerificationCommandValidator : ICommandValidator<ConfirmEmailVerificationCommand>
{
    public IEnumerable<string> Validate(ConfirmEmailVerificationCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Code))
        {
            yield return "Email verification code is required.";
        }
        else if (command.Code.Trim().Length > 2_048)
        {
            yield return "Email verification code is too long.";
        }
    }
}
