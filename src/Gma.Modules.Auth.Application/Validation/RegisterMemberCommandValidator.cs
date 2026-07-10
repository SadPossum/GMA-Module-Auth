namespace Gma.Modules.Auth.Application.Validation;

using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;
using Gma.Framework.Cqrs;

internal sealed class RegisterMemberCommandValidator : ICommandValidator<RegisterMemberCommand>
{
    public IEnumerable<string> Validate(RegisterMemberCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Username))
        {
            yield return "Username is required.";
        }

        if (string.IsNullOrEmpty(command.Password) || command.Password.Length < AuthPasswordPolicy.MinimumLength)
        {
            yield return AuthPasswordPolicy.MinimumLengthMessage;
        }

        if (command.Password?.Length > AuthPasswordPolicy.MaximumLength)
        {
            yield return AuthPasswordPolicy.MaximumLengthMessage;
        }
    }
}
