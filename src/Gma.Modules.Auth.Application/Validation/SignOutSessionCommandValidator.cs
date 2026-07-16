namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

internal sealed class SignOutSessionCommandValidator : ICommandValidator<SignOutSessionCommand>
{
    public IEnumerable<string> Validate(SignOutSessionCommand command)
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
