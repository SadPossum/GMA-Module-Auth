namespace Gma.Modules.Auth.Application.Validation;

using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Queries;

internal sealed class ListAuthenticationSessionsQueryValidator : IQueryValidator<ListAuthenticationSessionsQuery>
{
    public IEnumerable<string> Validate(ListAuthenticationSessionsQuery query)
    {
        if (query.MemberId == Guid.Empty)
        {
            yield return "Member id is required.";
        }

        if (query.CurrentSessionId == Guid.Empty)
        {
            yield return "Current session id is required.";
        }
    }
}
