namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.ExternalAuthentication;

internal sealed class CreateExternalAuthenticationHandoffCommandValidator
    : ICommandValidator<CreateExternalAuthenticationHandoffCommand>
{
    public IEnumerable<string> Validate(CreateExternalAuthenticationHandoffCommand command)
    {
        if (command.Identity is null)
        {
            yield return "A validated external identity is required.";
        }

        if (string.IsNullOrWhiteSpace(command.ReturnUrl) || command.ReturnUrl.Trim().Length > 2_048)
        {
            yield return "A valid external authentication return URL is required.";
        }

        bool invalidTargetMember = command.TargetMemberId is null || command.TargetMemberId == Guid.Empty;
        bool invalidTargetSession = command.TargetSessionId is null || command.TargetSessionId == Guid.Empty;
        if (command.Intent == ExternalAuthenticationIntent.Link && (invalidTargetMember || invalidTargetSession))
        {
            yield return "Link handoffs require a member and session.";
        }
    }
}
