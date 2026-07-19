namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Queries;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class GetMultiFactorStatusQueryHandler(
    IMemberRepository memberRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    ITimeBasedOneTimePasswordProvider totpProvider,
    IAuthenticatorSecretProtector secretProtector,
    ISystemClock clock)
    : IQueryHandler<GetMultiFactorStatusQuery, MultiFactorStatusResponse>
{
    public async Task<Result<MultiFactorStatusResponse>> HandleAsync(
        GetMultiFactorStatusQuery query,
        CancellationToken cancellationToken)
    {
        MemberId memberId = new(query.MemberId);
        if (await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false) is null)
        {
            return Result.Failure<MultiFactorStatusResponse>(AuthDomainErrors.MemberNotFound);
        }

        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        bool isPending = authenticator?.IsPendingAt(clock.UtcNow) == true;
        return Result.Success(new MultiFactorStatusResponse(
            totpProvider.IsAvailable && secretProtector.IsAvailable,
            isPending,
            authenticator?.IsActive == true,
            authenticator?.UnusedRecoveryCodeCount ?? 0,
            isPending ? authenticator!.EnrollmentExpiresAtUtc : null,
            authenticator?.ActivatedAtUtc,
            authenticator?.RecoveryCodesRegeneratedAtUtc));
    }
}
