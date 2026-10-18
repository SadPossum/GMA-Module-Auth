namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;

internal sealed class RememberedBrowserCommandValidator : ICommandValidator<RememberedBrowserCommand>
{
    public IEnumerable<string> Validate(RememberedBrowserCommand command)
    {
        RememberedBrowserOperation operation = command.Operation;
        if (!Enum.IsDefined(operation.Kind))
        {
            yield return "Remembered-browser operation kind is invalid.";
        }

        if (operation.ExpectedGeneration < 0)
        {
            yield return "Expected generation cannot be negative.";
        }

        if (operation.Kind is not (RememberedBrowserOperationKind.Device or RememberedBrowserOperationKind.Activity) &&
            operation.OperationId == Guid.Empty)
        {
            yield return "Operation id is required.";
        }
    }
}
