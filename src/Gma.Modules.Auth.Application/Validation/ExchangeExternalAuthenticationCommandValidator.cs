namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;

internal sealed class ExchangeExternalAuthenticationCommandValidator
    : ICommandValidator<ExchangeExternalAuthenticationCommand>
{
    public IEnumerable<string> Validate(ExchangeExternalAuthenticationCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Code))
        {
            yield return "External authentication exchange code is required.";
        }
        else if (command.Code.Trim().Length > 2_048)
        {
            yield return "External authentication exchange code is too long.";
        }
    }
}
