namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.Extensions.Options;
using Gma.Framework.Cqrs;
using Gma.Modules.Auth.Application.Ports;
using Gma.Framework.Runtime.Time;
using Gma.Framework.Results;

internal sealed class RefreshMemberSessionCommandHandler(
    IMemberRepository memberRepository,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock)
    : ICommandHandler<RefreshMemberSessionCommand, AuthTokensResponse>
{
    public async Task<Result<AuthTokensResponse>> HandleAsync(
        RefreshMemberSessionCommand command,
        CancellationToken cancellationToken)
    {
        AccessTokenClaims? claims = tokenService.GetAccessTokenClaims(command.AccessToken, validateLifetime: false);

        if (claims is null)
        {
            return Result.Failure<AuthTokensResponse>(AuthApplicationErrors.TokenInvalid);
        }

        if (scopeContext.IsEnabled &&
            !string.Equals(scopeContext.ScopeId, claims.ScopeId, StringComparison.Ordinal))
        {
            return Result.Failure<AuthTokensResponse>(AuthApplicationErrors.TenantMismatch);
        }

        Member? member = await memberRepository.GetByIdAsync(claims.MemberId, cancellationToken).ConfigureAwait(false);

        if (member is null)
        {
            return Result.Failure<AuthTokensResponse>(AuthDomainErrors.MemberNotFound);
        }

        string accessToken = tokenService.GenerateAccessToken(member.Id, member.ScopeId, claims.SessionId);
        string refreshToken = tokenService.GenerateRefreshToken();
        IReadOnlyList<string> refreshTokenHashes = refreshTokenHashingService.GetCandidateHashes(command.RefreshToken);
        string newRefreshTokenHash = refreshTokenHashingService.HashRefreshToken(refreshToken);

        Result refreshResult = member.RefreshSession(
            claims.SessionId,
            refreshTokenHashes,
            newRefreshTokenHash,
            clock.UtcNow.AddDays(options.Value.RefreshTokenLifetimeDays),
            clock.UtcNow);

        return refreshResult.IsSuccess
            ? Result.Success(new AuthTokensResponse(accessToken, refreshToken))
            : Result.Failure<AuthTokensResponse>(refreshResult.Error);
    }
}
