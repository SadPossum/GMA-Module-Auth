namespace Gma.Modules.Auth.Application.Queries;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record ListAuthenticationSessionsQuery(Guid MemberId, Guid CurrentSessionId)
    : IQuery<AuthenticationSessionsResponse>;
