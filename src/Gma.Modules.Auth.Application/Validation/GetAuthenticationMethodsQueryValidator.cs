namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Queries;

internal sealed class GetAuthenticationMethodsQueryValidator : IQueryValidator<GetAuthenticationMethodsQuery>
{
    public IEnumerable<string> Validate(GetAuthenticationMethodsQuery query)
    {
        if (query.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }
    }
}
