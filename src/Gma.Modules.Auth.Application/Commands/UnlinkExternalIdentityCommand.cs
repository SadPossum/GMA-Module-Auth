namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;

public sealed record UnlinkExternalIdentityCommand(
    Guid MemberId,
    Guid SessionId,
    Guid ExternalIdentityId,
    string? CurrentPassword)
    : ITransactionalCommand<Unit>;
