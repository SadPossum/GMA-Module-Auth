namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;

internal sealed class RequestPasswordRecoveryCommandValidator : ICommandValidator<RequestPasswordRecoveryCommand>
{
    public IEnumerable<string> Validate(RequestPasswordRecoveryCommand command)
    {
        if (!MemberUsername.IsValid(command.Email, MemberUsernameType.Email))
        {
            yield return "A valid email address is required.";
        }
    }
}
