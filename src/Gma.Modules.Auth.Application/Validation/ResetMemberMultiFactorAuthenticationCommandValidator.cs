namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Domain.Aggregates;

internal sealed class ResetMemberMultiFactorAuthenticationCommandValidator
    : ICommandValidator<ResetMemberMultiFactorAuthenticationCommand>
{
    public IEnumerable<string> Validate(ResetMemberMultiFactorAuthenticationCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (string.IsNullOrWhiteSpace(command.ActorId) ||
            command.ActorId.Trim().Length > MemberTotpAuthenticator.AdministrativeActorIdMaxLength ||
            command.ActorId.Any(char.IsControl))
        {
            yield return "Administrative actor id is invalid.";
        }

        if (string.IsNullOrWhiteSpace(command.Reason) ||
            command.Reason.Trim().Length > MemberTotpAuthenticator.AdministrativeResetReasonMaxLength ||
            command.Reason.Any(char.IsControl))
        {
            yield return "Reset reason is required and must be 512 characters or fewer.";
        }
    }
}
