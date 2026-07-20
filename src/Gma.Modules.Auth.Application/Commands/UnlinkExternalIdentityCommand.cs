namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record UnlinkExternalIdentityCommand(
    Guid MemberId,
    Guid SessionId,
    Guid ExternalIdentityId,
    string? CurrentPassword,
    string RefreshToken)
    : ITransactionalCommand<RefreshTokenBoundCompletion<AuthTokensResponse>>;
