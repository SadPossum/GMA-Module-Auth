namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record StepUpWithPasswordCommand(
    Guid MemberId,
    Guid SessionId,
    string Password,
    string RefreshToken) : ITransactionalCommand<RefreshTokenBoundCompletion<AuthTokensResponse>>;
