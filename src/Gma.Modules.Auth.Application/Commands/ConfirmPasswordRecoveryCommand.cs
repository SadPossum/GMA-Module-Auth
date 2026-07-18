namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;

public sealed record ConfirmPasswordRecoveryCommand(string Code, string NewPassword)
    : ITransactionalCommand<Unit>;
