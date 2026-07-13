namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Modules.Auth.Application.Queries;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class GetAuthenticationMethodsQueryHandler(IMemberRepository memberRepository)
    : IQueryHandler<GetAuthenticationMethodsQuery, AuthenticationMethodsResponse>
{
    public async Task<Result<AuthenticationMethodsResponse>> HandleAsync(
        GetAuthenticationMethodsQuery query,
        CancellationToken cancellationToken)
    {
        Member? member = await memberRepository
            .GetByIdAsync(new MemberId(query.MemberId), cancellationToken)
            .ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<AuthenticationMethodsResponse>(AuthDomainErrors.MemberNotFound);
        }

        return Result.Success(new AuthenticationMethodsResponse(
            member.HasPassword,
            member.Usernames
                .Where(username => username.UsernameType == MemberUsernameType.Email)
                .OrderByDescending(username => username.IsActive)
                .ThenBy(username => username.Value, StringComparer.OrdinalIgnoreCase)
                .Select(username => new AuthenticationEmailResponse(
                    username.Id.Value,
                    username.Value,
                    username.IsActive,
                    username.IsVerified,
                    username.VerifiedAtUtc))
                .ToArray(),
            member.ExternalIdentities
                .OrderBy(identity => identity.ProviderCode, StringComparer.Ordinal)
                .Select(identity => new ExternalIdentityResponse(
                    identity.Id.Value,
                    identity.ProviderCode,
                    identity.LinkedAtUtc,
                    identity.LastAuthenticatedAtUtc))
                .ToArray()));
    }
}
