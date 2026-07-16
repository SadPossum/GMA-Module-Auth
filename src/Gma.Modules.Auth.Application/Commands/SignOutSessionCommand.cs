namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;

public sealed record SignOutSessionCommand(Guid MemberId, Guid SessionId) : ITransactionalCommand<Unit>;
