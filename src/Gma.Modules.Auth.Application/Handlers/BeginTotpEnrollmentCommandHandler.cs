namespace Gma.Modules.Auth.Application.Handlers;

using System.Security.Cryptography;
using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

internal sealed class BeginTotpEnrollmentCommandHandler(
    IMemberRepository memberRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    ITimeBasedOneTimePasswordProvider totpProvider,
    IAuthenticatorSecretProtector secretProtector,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : ICommandHandler<BeginTotpEnrollmentCommand, TotpEnrollmentResponse>
{
    public async Task<Result<TotpEnrollmentResponse>> HandleAsync(
        BeginTotpEnrollmentCommand command,
        CancellationToken cancellationToken)
    {
        if (!totpProvider.IsAvailable || !secretProtector.IsAvailable)
        {
            return Result.Failure<TotpEnrollmentResponse>(AuthApplicationErrors.MultiFactorProviderUnavailable);
        }

        MemberId memberId = new(command.MemberId);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null ||
            (scopeContext.IsEnabled && !string.Equals(scopeContext.ScopeId, member.ScopeId, StringComparison.Ordinal)))
        {
            return Result.Failure<TotpEnrollmentResponse>(AuthDomainErrors.MemberNotFound);
        }

        DateTimeOffset nowUtc = clock.UtcNow;
        Result<MemberSession> freshSession = MemberSecurityAuthorization.RequireFreshSession(
            member,
            command.SessionId,
            nowUtc,
            TimeSpan.FromMinutes(options.Value.MultiFactor.SensitiveSessionFreshnessMinutes));
        if (freshSession.IsFailure ||
            string.Equals(
                freshSession.Value.AuthenticationContextReference,
                AuthenticationContextReferences.Legacy,
                StringComparison.Ordinal))
        {
            return Result.Failure<TotpEnrollmentResponse>(AuthApplicationErrors.FreshAuthenticationRequired);
        }

        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (authenticator?.IsActive == true)
        {
            return Result.Failure<TotpEnrollmentResponse>(AuthApplicationErrors.TotpAuthenticatorAlreadyActive);
        }

        MemberUsername? username = member.Usernames
            .Where(item => item.IsActive)
            .OrderBy(item => item.UsernameType)
            .FirstOrDefault();
        if (username is null)
        {
            return Result.Failure<TotpEnrollmentResponse>(AuthDomainErrors.UsernameNotValid);
        }

        GeneratedTotpSecret generatedSecret = totpProvider.GenerateSecret();
        try
        {
            string protectedSecret = secretProtector.Protect(generatedSecret.Bytes);
            DateTimeOffset expiresAtUtc = nowUtc.AddMinutes(options.Value.MultiFactor.EnrollmentLifetimeMinutes);
            Result enrollment;
            if (authenticator is null)
            {
                Result<MemberTotpAuthenticator> created = MemberTotpAuthenticator.BeginEnrollment(
                    new MemberTotpAuthenticatorId(idGenerator.NewId()),
                    memberId,
                    member.ScopeId,
                    protectedSecret,
                    expiresAtUtc,
                    nowUtc);
                if (created.IsFailure)
                {
                    return Result.Failure<TotpEnrollmentResponse>(created.Error);
                }

                await authenticatorRepository.AddAsync(created.Value, cancellationToken).ConfigureAwait(false);
                enrollment = Result.Success();
            }
            else
            {
                enrollment = authenticator.RestartEnrollment(protectedSecret, expiresAtUtc, nowUtc);
            }

            if (enrollment.IsFailure)
            {
                return Result.Failure<TotpEnrollmentResponse>(enrollment.Error);
            }

            return Result.Success(new TotpEnrollmentResponse(
                generatedSecret.Encoded,
                totpProvider.CreateProvisioningUri(username.Value, generatedSecret.Encoded),
                expiresAtUtc));
        }
        catch (CryptographicException)
        {
            return Result.Failure<TotpEnrollmentResponse>(AuthApplicationErrors.MultiFactorProviderUnavailable);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(generatedSecret.Bytes);
        }
    }
}
