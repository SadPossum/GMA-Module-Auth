namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record RemoveMemberPasswordCommand(
    Guid MemberId,
    Guid SessionId,
    string CurrentPassword,
    string RefreshToken)
    : ITransactionalCommand<RefreshTokenBoundCompletion<AuthTokensResponse>>;
