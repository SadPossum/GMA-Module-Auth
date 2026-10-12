namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;

internal sealed class RememberedBrowserCommandHandler(IRememberedBrowserService service)
    : ICommandHandler<RememberedBrowserCommand, RememberedBrowserCompletion>
{
    public async Task<Result<RememberedBrowserCompletion>> HandleAsync(
        RememberedBrowserCommand command,
        CancellationToken cancellationToken) =>
        Result.Success(await service.ExecuteAsync(command.Operation, cancellationToken).ConfigureAwait(false));
}
