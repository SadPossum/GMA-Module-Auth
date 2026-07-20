namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record SetMemberPasswordCommand(
    Guid MemberId,
    Guid SessionId,
    string NewPassword,
    string? CurrentPassword,
    string RefreshToken)
    : ITransactionalCommand<RefreshTokenBoundCompletion<AuthTokensResponse>>;
