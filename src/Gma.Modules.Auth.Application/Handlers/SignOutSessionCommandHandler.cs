namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class SignOutSessionCommandHandler(IMemberRepository memberRepository, ISystemClock clock)
    : ICommandHandler<SignOutSessionCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(
        SignOutSessionCommand command,
        CancellationToken cancellationToken)
    {
        Member? member = await memberRepository
            .GetByIdAsync(new MemberId(command.MemberId), cancellationToken)
            .ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<Unit>(AuthDomainErrors.MemberNotFound);
        }

        Result result = member.SignOutSession(new MemberSessionId(command.SessionId), clock.UtcNow);
        return result.IsSuccess
            ? Result.Success(Unit.Value)
            : Result.Failure<Unit>(result.Error);
    }
}
