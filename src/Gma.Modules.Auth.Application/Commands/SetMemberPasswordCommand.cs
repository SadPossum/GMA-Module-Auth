namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;

public sealed record SetMemberPasswordCommand(
    Guid MemberId,
    Guid SessionId,
    string NewPassword,
    string? CurrentPassword)
    : ITransactionalCommand<Unit>;
