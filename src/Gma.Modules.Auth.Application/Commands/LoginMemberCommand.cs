namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record LoginMemberCommand(
    string Username,
    string Password,
    string? IpAddress = null,
    string? UserAgent = null) : ITransactionalCommand<PrimaryAuthenticationResult>;
