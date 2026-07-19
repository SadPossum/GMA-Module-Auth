namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
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

internal sealed class RemoveMemberPasswordCommandHandler(
    IMemberRepository memberRepository,
    PasswordProofService passwordProofService,
    ISystemClock clock,
    IIdGenerator idGenerator,
    IOptions<AuthApplicationOptions> options)
    : ICommandHandler<RemoveMemberPasswordCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(RemoveMemberPasswordCommand command, CancellationToken cancellationToken)
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

        PasswordVerificationOutcome password = await passwordProofService.VerifyAsync(
            member.ScopeId,
            AuthenticationAttemptPurposes.PasswordRemoval,
            command.MemberId.ToString("D", System.Globalization.CultureInfo.InvariantCulture),
            member.PasswordHash,
            command.CurrentPassword,
            clock.UtcNow,
            cancellationToken).ConfigureAwait(false);
        if (password == PasswordVerificationOutcome.Unknown)
        {
            return Result.Failure<Unit>(AuthDomainErrors.CredentialsNotValid);
        }

        Result result = member.RemovePassword();
        if (result.IsFailure)
        {
            return Result.Failure<Unit>(result.Error);
        }

        Result changed = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Password,
            MemberAuthenticationMethodChange.Removed,
            idGenerator.NewId(),
            clock.UtcNow);
        return changed.IsSuccess ? Result.Success(Unit.Value) : Result.Failure<Unit>(changed.Error);
    }
}
