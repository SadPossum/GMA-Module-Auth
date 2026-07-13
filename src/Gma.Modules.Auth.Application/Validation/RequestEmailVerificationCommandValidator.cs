namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

internal sealed class RequestEmailVerificationCommandValidator : ICommandValidator<RequestEmailVerificationCommand>
{
    public IEnumerable<string> Validate(RequestEmailVerificationCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.EmailId == Guid.Empty)
        {
            yield return "Email id must be omitted or non-empty.";
        }
    }
}
