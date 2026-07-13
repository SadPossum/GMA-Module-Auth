namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;

public sealed record RemoveMemberPasswordCommand(Guid MemberId, Guid SessionId, string CurrentPassword)
    : ITransactionalCommand<Unit>;
