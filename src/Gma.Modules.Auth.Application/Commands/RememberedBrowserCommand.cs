namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Ports;

public sealed record RememberedBrowserCommand(RememberedBrowserOperation Operation)
    : ITransactionalCommand<RememberedBrowserCompletion>;
