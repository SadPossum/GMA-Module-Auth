namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;

public sealed record RequestPasswordRecoveryCommand(string Email) : ITransactionalCommand<Unit>;
