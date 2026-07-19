namespace Gma.Modules.Auth.Application.Commands;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record BeginTotpEnrollmentCommand(Guid MemberId, Guid SessionId)
    : ITransactionalCommand<TotpEnrollmentResponse>;
