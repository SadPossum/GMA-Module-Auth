namespace Gma.Modules.Auth.Application.Security;

using System.Security.Cryptography;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;
using DomainMemberStatus = Gma.Modules.Auth.Domain.Enums.MemberStatus;

internal sealed class MultiFactorAuthenticationService(
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    IMemberAuthenticationChallengeRepository challengeRepository,
    IAuthenticationChallengeRequestSerializer challengeRequestSerializer,
    ITimeBasedOneTimePasswordProvider totpProvider,
    IAuthenticatorSecretProtector secretProtector,
    IMultiFactorTokenService tokenService,
    IOptions<AuthApplicationOptions> options,
    ISystemClock clock,
    IIdGenerator idGenerator)
{
    public bool TotpProviderAvailable => totpProvider.IsAvailable && secretProtector.IsAvailable;

    public async Task<Result<MultiFactorChallengeRequirement>> CreateChallengeIfRequiredAsync(
        Member member,
        string primaryAuthenticationMethod,
        SessionAuthenticationEvidence primaryEvidence,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        if (member.Status != DomainMemberStatus.Active)
        {
            return Result.Failure<MultiFactorChallengeRequirement>(
                member.Status == DomainMemberStatus.Disabled
                    ? AuthDomainErrors.MemberDisabled
                    : AuthDomainErrors.MemberStatusUnknown);
        }

        await challengeRequestSerializer
            .AcquireAsync(member.ScopeId, member.Id, cancellationToken)
            .ConfigureAwait(false);

        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(member.Id, cancellationToken)
            .ConfigureAwait(false);
        if (authenticator is null || !authenticator.IsActive)
        {
            return Result.Success(MultiFactorChallengeRequirement.NotRequired);
        }

        List<MultiFactorCodeType> availableCodeTypes = [];
        if (this.TotpProviderAvailable)
        {
            availableCodeTypes.Add(MultiFactorCodeType.Totp);
        }

        if (authenticator.UnusedRecoveryCodeCount > 0)
        {
            availableCodeTypes.Add(MultiFactorCodeType.RecoveryCode);
        }

        if (availableCodeTypes.Count == 0)
        {
            return Result.Failure<MultiFactorChallengeRequirement>(AuthApplicationErrors.MultiFactorProviderUnavailable);
        }

        DateTimeOffset nowUtc = clock.UtcNow;
        IReadOnlyList<MemberAuthenticationChallenge> activeChallenges = await challengeRepository
            .GetActiveByMemberAsync(member.Id, nowUtc, cancellationToken)
            .ConfigureAwait(false);
        foreach (MemberAuthenticationChallenge activeChallenge in activeChallenges)
        {
            activeChallenge.Revoke(nowUtc);
        }

        MultiFactorTokenMaterial token = tokenService.GenerateChallengeToken();
        DateTimeOffset expiresAtUtc = nowUtc.AddMinutes(options.Value.MultiFactor.ChallengeLifetimeMinutes);
        Result<MemberAuthenticationChallenge> challenge = MemberAuthenticationChallenge.Create(
            new MemberAuthenticationChallengeId(idGenerator.NewId()),
            member.Id,
            member.ScopeId,
            token.Hash,
            primaryAuthenticationMethod,
            primaryEvidence,
            ipAddress,
            userAgent,
            options.Value.MultiFactor.ChallengeMaximumAttempts,
            expiresAtUtc,
            nowUtc);
        if (challenge.IsFailure)
        {
            return Result.Failure<MultiFactorChallengeRequirement>(challenge.Error);
        }

        await challengeRepository.AddAsync(challenge.Value, cancellationToken).ConfigureAwait(false);
        return Result.Success(MultiFactorChallengeRequirement.Required(
            new MultiFactorChallengeResponse(
                token.Plaintext,
                expiresAtUtc,
                availableCodeTypes)));
    }

    public Result<SessionAuthenticationEvidence> VerifyFactor(
        MemberTotpAuthenticator authenticator,
        SessionAuthenticationEvidence primaryEvidence,
        MultiFactorCodeType codeType,
        string code,
        DateTimeOffset nowUtc)
    {
        if (codeType == MultiFactorCodeType.Totp)
        {
            if (!this.TotpProviderAvailable || authenticator.ProtectedSecret is null)
            {
                return Result.Failure<SessionAuthenticationEvidence>(AuthApplicationErrors.MultiFactorProviderUnavailable);
            }

            Result<long> verification = this.VerifyTotpCode(authenticator.ProtectedSecret, code, nowUtc);
            if (verification.IsFailure)
            {
                return Result.Failure<SessionAuthenticationEvidence>(verification.Error);
            }

            Result accepted = authenticator.AcceptTotp(verification.Value);
            return accepted.IsSuccess
                ? Result.Success(SessionAuthenticationEvidence.CompleteWithTotp(primaryEvidence, nowUtc))
                : Result.Failure<SessionAuthenticationEvidence>(AuthApplicationErrors.MultiFactorChallengeInvalid);
        }

        if (codeType == MultiFactorCodeType.RecoveryCode)
        {
            IReadOnlyList<string> candidateHashes = tokenService.GetCandidateRecoveryCodeHashes(code);
            Result consumed = authenticator.ConsumeRecoveryCode(candidateHashes, nowUtc);
            return consumed.IsSuccess
                ? Result.Success(SessionAuthenticationEvidence.CompleteWithRecoveryCode(primaryEvidence, nowUtc))
                : Result.Failure<SessionAuthenticationEvidence>(AuthApplicationErrors.MultiFactorChallengeInvalid);
        }

        return Result.Failure<SessionAuthenticationEvidence>(AuthApplicationErrors.MultiFactorChallengeInvalid);
    }

    public Result<long> VerifyPendingTotp(
        MemberTotpAuthenticator authenticator,
        string code,
        DateTimeOffset nowUtc) =>
        authenticator.IsPendingAt(nowUtc) && authenticator.ProtectedSecret is not null
            ? this.VerifyTotpCode(authenticator.ProtectedSecret, code, nowUtc)
            : Result.Failure<long>(AuthApplicationErrors.TotpEnrollmentInvalid);

    public IReadOnlyList<RecoveryCodeMaterial> GenerateRecoveryCodes() =>
        tokenService.GenerateRecoveryCodes(options.Value.MultiFactor.RecoveryCodeCount);

    public IReadOnlyList<TotpRecoveryCodeRegistration> CreateRecoveryCodeRegistrations(
        IReadOnlyList<RecoveryCodeMaterial> recoveryCodes) =>
        recoveryCodes.Select(code => new TotpRecoveryCodeRegistration(
            new MemberTotpRecoveryCodeId(idGenerator.NewId()),
            code.Hash)).ToArray();

    public IReadOnlyList<string> GetCandidateChallengeTokenHashes(string token) =>
        tokenService.GetCandidateChallengeTokenHashes(token);

    private Result<long> VerifyTotpCode(string protectedSecret, string code, DateTimeOffset nowUtc)
    {
        if (!this.TotpProviderAvailable)
        {
            return Result.Failure<long>(AuthApplicationErrors.MultiFactorProviderUnavailable);
        }

        byte[]? secret = null;
        try
        {
            secret = secretProtector.Unprotect(protectedSecret);
            TotpVerificationResult verification = totpProvider.Verify(secret, code.Trim(), nowUtc);
            return verification.IsValid
                ? Result.Success(verification.MatchedTimeStep)
                : Result.Failure<long>(AuthApplicationErrors.MultiFactorChallengeInvalid);
        }
        catch (CryptographicException)
        {
            return Result.Failure<long>(AuthApplicationErrors.MultiFactorProviderUnavailable);
        }
        catch (FormatException)
        {
            return Result.Failure<long>(AuthApplicationErrors.MultiFactorProviderUnavailable);
        }
        finally
        {
            if (secret is not null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }
}
