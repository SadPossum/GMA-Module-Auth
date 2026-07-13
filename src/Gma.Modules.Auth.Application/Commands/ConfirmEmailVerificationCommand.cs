namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;

public sealed record ConfirmEmailVerificationCommand(string Code) : ITransactionalCommand<Unit>;
