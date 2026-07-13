namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

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
    }
}
