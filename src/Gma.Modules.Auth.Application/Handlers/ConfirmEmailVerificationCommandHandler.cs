namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;

internal sealed class ConfirmEmailVerificationCommandHandler(
    IMemberRepository memberRepository,
    IAuthOneTimeTokenService tokenService,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : ICommandHandler<ConfirmEmailVerificationCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(
        ConfirmEmailVerificationCommand command,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> candidateHashes = tokenService.GetCandidateHashes(
            AuthOneTimeTokenPurpose.EmailVerification,
            command.Code.Trim());
        EmailVerificationTarget? target = await memberRepository
            .GetByEmailVerificationTokenHashesAsync(candidateHashes, cancellationToken)
            .ConfigureAwait(false);
        if (target is null)
        {
            return Result.Failure<Unit>(AuthApplicationErrors.EmailVerificationInvalid);
        }

        Result result = target.Member.ConfirmEmailVerification(
            target.UsernameId,
            target.MatchedTokenHash,
            idGenerator.NewId(),
            clock.UtcNow);
        return result.IsSuccess ? Result.Success(Unit.Value) : Result.Failure<Unit>(result.Error);
    }
}
