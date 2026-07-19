namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Queries;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class ListAuthenticationSessionsQueryHandler(
    IMemberRepository memberRepository,
    ISystemClock clock)
    : IQueryHandler<ListAuthenticationSessionsQuery, AuthenticationSessionsResponse>
{
    public async Task<Result<AuthenticationSessionsResponse>> HandleAsync(
        ListAuthenticationSessionsQuery query,
        CancellationToken cancellationToken)
    {
        Member? member = await memberRepository
            .GetByIdAsync(new MemberId(query.MemberId), cancellationToken)
            .ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<AuthenticationSessionsResponse>(AuthDomainErrors.MemberNotFound);
        }

        AuthenticationSessionResponse[] sessions = member.Sessions
            .Where(session => session.IsActive && session.RefreshTokenExpiresAtUtc > clock.UtcNow)
            .OrderByDescending(session => session.Id.Value == query.CurrentSessionId)
            .ThenByDescending(session => session.LoginDateTimeUtc)
            .Select(session => new AuthenticationSessionResponse(
                session.Id.Value,
                session.AuthenticationMethod,
                session.LoginDateTimeUtc,
                session.RefreshTokenExpiresAtUtc,
                session.Id.Value == query.CurrentSessionId))
            .ToArray();

        return Result.Success(new AuthenticationSessionsResponse(sessions));
    }
}
