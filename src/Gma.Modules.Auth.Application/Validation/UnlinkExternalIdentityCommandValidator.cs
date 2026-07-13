namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

internal sealed class UnlinkExternalIdentityCommandValidator : ICommandValidator<UnlinkExternalIdentityCommand>
{
    public IEnumerable<string> Validate(UnlinkExternalIdentityCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
        }

        if (command.ExternalIdentityId == Guid.Empty)
        {
            yield return "External identity id is required.";
        }
    }
}
