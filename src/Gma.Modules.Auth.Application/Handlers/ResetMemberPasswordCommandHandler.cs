namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Modules.Auth.Application.Security;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;

internal sealed class ResetMemberPasswordCommandHandler(
    IMemberRepository memberRepository,
    IPasswordHashingService passwordHashingService,
    IPasswordBlocklist passwordBlocklist,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : ICommandHandler<ResetMemberPasswordCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(ResetMemberPasswordCommand command, CancellationToken cancellationToken)
    {
        Member? member = await memberRepository.GetByIdAsync(new MemberId(command.MemberId), cancellationToken).ConfigureAwait(false);

        if (member is null)
        {
            return Result.Failure<Unit>(AuthDomainErrors.MemberNotFound);
        }

        if (await passwordBlocklist.IsBlockedAsync(command.NewPassword, cancellationToken).ConfigureAwait(false))
        {
            return Result.Failure<Unit>(AuthApplicationErrors.PasswordBlocked);
        }

        bool hadPassword = member.HasPassword;
        Result result = member.ResetPassword(passwordHashingService.HashPassword(command.NewPassword));
        if (result.IsFailure)
        {
            return Result.Failure<Unit>(result.Error);
        }

        Result<int> revoked = member.RevokeSessions(idGenerator.NewId(), clock.UtcNow);
        if (revoked.IsFailure)
        {
            return Result.Failure<Unit>(revoked.Error);
        }

        Result changed = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Password,
            hadPassword ? MemberAuthenticationMethodChange.Updated : MemberAuthenticationMethodChange.Added,
            idGenerator.NewId(),
            clock.UtcNow);
        return changed.IsSuccess ? Result.Success(Unit.Value) : Result.Failure<Unit>(changed.Error);
    }
}
