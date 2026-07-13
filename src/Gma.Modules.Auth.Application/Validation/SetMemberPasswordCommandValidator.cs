namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;

internal sealed class SetMemberPasswordCommandValidator : ICommandValidator<SetMemberPasswordCommand>
{
    public IEnumerable<string> Validate(SetMemberPasswordCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
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
