namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Time;
using Gma.Framework.Runtime.Identity;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

internal sealed class SetMemberPasswordCommandHandler(
    IMemberRepository memberRepository,
    IPasswordHashingService passwordHashingService,
    IPasswordBlocklist passwordBlocklist,
    ISystemClock clock,
    IIdGenerator idGenerator,
    IOptions<AuthApplicationOptions> options)
    : ICommandHandler<SetMemberPasswordCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(SetMemberPasswordCommand command, CancellationToken cancellationToken)
    {
        Member? member = await memberRepository
            .GetByIdAsync(new MemberId(command.MemberId), cancellationToken)
            .ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<Unit>(AuthDomainErrors.MemberNotFound);
        }

        Result freshSession = MemberSecurityAuthorization.RequireFreshSession(
            member,
            command.SessionId,
            clock.UtcNow,
            TimeSpan.FromMinutes(options.Value.ExternalLinkSessionFreshnessMinutes));
        if (freshSession.IsFailure)
        {
            return Result.Failure<Unit>(freshSession.Error);
        }

        if (member.HasPassword)
        {
            Result password = MemberSecurityAuthorization.RequirePassword(
                member,
                command.CurrentPassword,
                passwordHashingService);
            if (password.IsFailure)
            {
                return Result.Failure<Unit>(password.Error);
            }
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

        Result changed = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Password,
            hadPassword ? MemberAuthenticationMethodChange.Updated : MemberAuthenticationMethodChange.Added,
            idGenerator.NewId(),
            clock.UtcNow);
        return changed.IsSuccess ? Result.Success(Unit.Value) : Result.Failure<Unit>(changed.Error);
    }
}
