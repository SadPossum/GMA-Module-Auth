namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

internal sealed class StepUpWithPasswordCommandValidator : ICommandValidator<StepUpWithPasswordCommand>
{
    public IEnumerable<string> Validate(StepUpWithPasswordCommand command)
    {
        if (command.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (command.SessionId == Guid.Empty)
        {
            yield return "Session id is required.";
        }

        if (string.IsNullOrEmpty(command.Password))
        {
            yield return "Password is required.";
        }

        if (string.IsNullOrWhiteSpace(command.RefreshToken))
        {
            yield return "Refresh token is required.";
        }
    }
}
