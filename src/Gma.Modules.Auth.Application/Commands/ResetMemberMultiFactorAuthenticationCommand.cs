namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;

public sealed record ResetMemberMultiFactorAuthenticationCommand(
    Guid MemberId,
    string ActorId,
    string Reason) : ITransactionalCommand<Unit>;
