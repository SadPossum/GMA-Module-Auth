namespace Gma.Modules.Auth.Application.Queries;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record GetAuthenticationMethodsQuery(Guid MemberId) : IQuery<AuthenticationMethodsResponse>;
