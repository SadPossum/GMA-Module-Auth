namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Queries;

internal sealed class GetMultiFactorStatusQueryValidator : IQueryValidator<GetMultiFactorStatusQuery>
{
    public IEnumerable<string> Validate(GetMultiFactorStatusQuery query)
    {
        if (query.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }
    }
}
