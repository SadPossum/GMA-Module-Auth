namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

internal sealed class RequestEmailVerificationCommandHandler(
    IMemberRepository memberRepository,
    ITokenService tokenService,
    IRefreshTokenHashingService tokenHashingService,
    ISystemClock clock,
    IIdGenerator idGenerator,
    IOptions<AuthApplicationOptions> options)
    : ICommandHandler<RequestEmailVerificationCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(
        RequestEmailVerificationCommand command,
        CancellationToken cancellationToken)
    {
        Member? member = await memberRepository
            .GetByIdAsync(new MemberId(command.MemberId), cancellationToken)
            .ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<Unit>(AuthDomainErrors.MemberNotFound);
        }

        MemberUsername? email = member.Usernames.FirstOrDefault(username =>
            username.UsernameType == MemberUsernameType.Email &&
            username.IsActive &&
            (command.EmailId is null || username.Id.Value == command.EmailId.Value));
        if (email is null)
        {
            return Result.Failure<Unit>(AuthDomainErrors.EmailUsernameNotFound);
        }

        DateTimeOffset nowUtc = clock.UtcNow;
        if (email.VerificationRequestedAtUtc is { } requestedAtUtc &&
            requestedAtUtc.AddSeconds(options.Value.EmailVerificationRequestCooldownSeconds) > nowUtc)
        {
            return Result.Failure<Unit>(AuthApplicationErrors.EmailVerificationRequestTooSoon);
        }

        string code = tokenService.GenerateRefreshToken();
        Result result = member.RequestEmailVerification(
            email.Id,
            tokenHashingService.HashRefreshToken(code),
            code,
            idGenerator.NewId(),
            nowUtc.AddMinutes(options.Value.EmailVerificationLifetimeMinutes),
            nowUtc);
        return result.IsSuccess ? Result.Success(Unit.Value) : Result.Failure<Unit>(result.Error);
    }
}
