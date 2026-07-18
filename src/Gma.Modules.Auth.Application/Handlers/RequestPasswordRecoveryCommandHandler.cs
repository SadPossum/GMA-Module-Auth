namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

internal sealed class RequestPasswordRecoveryCommandHandler(
    IPasswordRecoveryRecipientReader recipientReader,
    IPasswordRecoveryChallengeRepository challengeRepository,
    IPasswordRecoveryTokenService tokenService,
    ISystemClock clock,
    IIdGenerator idGenerator,
    IOptions<AuthApplicationOptions> options)
    : ICommandHandler<RequestPasswordRecoveryCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(
        RequestPasswordRecoveryCommand command,
        CancellationToken cancellationToken)
    {
        PasswordRecoveryRecipient? recipient = await recipientReader
            .FindEligibleByEmailAsync(command.Email, cancellationToken)
            .ConfigureAwait(false);
        if (recipient is null)
        {
            return Result.Success(Unit.Value);
        }

        DateTimeOffset nowUtc = clock.UtcNow;
        MemberId memberId = new(recipient.MemberId);
        PasswordRecoveryChallenge? latest = await challengeRepository
            .GetLatestByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (latest is not null &&
            latest.RequestedAtUtc.AddSeconds(options.Value.PasswordRecoveryRequestCooldownSeconds) > nowUtc)
        {
            return Result.Success(Unit.Value);
        }

        IReadOnlyList<PasswordRecoveryChallenge> activeChallenges = await challengeRepository
            .GetActiveByMemberAsync(memberId, nowUtc, cancellationToken)
            .ConfigureAwait(false);
        foreach (PasswordRecoveryChallenge activeChallenge in activeChallenges)
        {
            activeChallenge.Revoke(nowUtc);
        }

        string code = tokenService.GenerateCode();
        Result<PasswordRecoveryChallenge> challengeResult = PasswordRecoveryChallenge.Create(
            new PasswordRecoveryChallengeId(idGenerator.NewId()),
            memberId,
            recipient.ScopeId,
            recipient.Email,
            tokenService.HashCode(code),
            code,
            idGenerator.NewId(),
            nowUtc.AddMinutes(options.Value.PasswordRecoveryLifetimeMinutes),
            nowUtc);
        if (challengeResult.IsFailure)
        {
            return Result.Failure<Unit>(challengeResult.Error);
        }

        await challengeRepository.AddAsync(challengeResult.Value, cancellationToken).ConfigureAwait(false);
        return Result.Success(Unit.Value);
    }
}
