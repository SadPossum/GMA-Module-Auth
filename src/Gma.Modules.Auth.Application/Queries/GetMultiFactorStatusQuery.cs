namespace Gma.Modules.Auth.Application.Queries;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Contracts;

public sealed record GetMultiFactorStatusQuery(Guid MemberId) : IQuery<MultiFactorStatusResponse>;
