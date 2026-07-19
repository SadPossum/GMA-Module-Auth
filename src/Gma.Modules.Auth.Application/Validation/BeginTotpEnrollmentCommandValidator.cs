namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

internal sealed class BeginTotpEnrollmentCommandValidator : ICommandValidator<BeginTotpEnrollmentCommand>
{
    public IEnumerable<string> Validate(BeginTotpEnrollmentCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
        }
    }
}
