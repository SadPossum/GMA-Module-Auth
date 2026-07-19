namespace Gma.Modules.Auth.Domain.Aggregates;

using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed class MemberTotpAuthenticator : ScopedAggregateRoot<MemberTotpAuthenticatorId>
{
    public const int ProtectedSecretMaxLength = 4_096;
    public const int RecoveryCodeLimit = 16;
    public const int AdministrativeResetReasonMaxLength = 512;
    public const int AdministrativeActorIdMaxLength = 256;

    private readonly List<MemberTotpRecoveryCode> recoveryCodes = [];

    private MemberTotpAuthenticator() { }

    private MemberTotpAuthenticator(
        MemberTotpAuthenticatorId id,
        MemberId memberId,
        string scopeId,
        string protectedSecret,
        DateTimeOffset enrollmentExpiresAtUtc,
        DateTimeOffset nowUtc)
        : base(id, scopeId)
    {
        this.MemberId = memberId;
        this.ProtectedSecret = protectedSecret;
        this.EnrollmentStartedAtUtc = nowUtc;
        this.EnrollmentExpiresAtUtc = enrollmentExpiresAtUtc;
        this.ConcurrencyStamp = Guid.CreateVersion7();
    }

    public MemberId MemberId { get; private set; }
    public string? ProtectedSecret { get; private set; }
    public DateTimeOffset EnrollmentStartedAtUtc { get; private set; }
    public DateTimeOffset EnrollmentExpiresAtUtc { get; private set; }
    public DateTimeOffset? ActivatedAtUtc { get; private set; }
    public DateTimeOffset? DisabledAtUtc { get; private set; }
    public DateTimeOffset? RecoveryCodesRegeneratedAtUtc { get; private set; }
    public long? LastAcceptedTimeStep { get; private set; }
    public Guid ConcurrencyStamp { get; private set; }
    public IReadOnlyCollection<MemberTotpRecoveryCode> RecoveryCodes => this.recoveryCodes.AsReadOnly();
    public bool IsActive => this.ActivatedAtUtc is not null && this.DisabledAtUtc is null;
    public int UnusedRecoveryCodeCount => this.recoveryCodes.Count(code => code.IsAvailable);

    public static Result<MemberTotpAuthenticator> BeginEnrollment(
        MemberTotpAuthenticatorId id,
        MemberId memberId,
        string scopeId,
        string protectedSecret,
        DateTimeOffset enrollmentExpiresAtUtc,
        DateTimeOffset nowUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<MemberTotpAuthenticator>(AuthDomainErrors.TotpAuthenticatorIdRequired);
        }

        if (memberId.Value == Guid.Empty ||
            !ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) ||
            !TryNormalizeProtectedSecret(protectedSecret, out string? normalizedSecret) ||
            enrollmentExpiresAtUtc <= nowUtc)
        {
            return Result.Failure<MemberTotpAuthenticator>(AuthDomainErrors.TotpAuthenticatorNotValid);
        }

        return Result.Success(new MemberTotpAuthenticator(
            id,
            memberId,
            normalizedScopeId,
            normalizedSecret,
            enrollmentExpiresAtUtc,
            nowUtc));
    }

    public Result RestartEnrollment(
        string protectedSecret,
        DateTimeOffset enrollmentExpiresAtUtc,
        DateTimeOffset nowUtc)
    {
        if (this.IsActive)
        {
            return Result.Failure(AuthDomainErrors.TotpAuthenticatorAlreadyActive);
        }

        if (!TryNormalizeProtectedSecret(protectedSecret, out string? normalizedSecret) ||
            enrollmentExpiresAtUtc <= nowUtc)
        {
            return Result.Failure(AuthDomainErrors.TotpAuthenticatorNotValid);
        }

        foreach (MemberTotpRecoveryCode recoveryCode in this.recoveryCodes)
        {
            recoveryCode.Revoke(nowUtc);
        }

        this.ProtectedSecret = normalizedSecret;
        this.EnrollmentStartedAtUtc = nowUtc;
        this.EnrollmentExpiresAtUtc = enrollmentExpiresAtUtc;
        this.ActivatedAtUtc = null;
        this.DisabledAtUtc = null;
        this.RecoveryCodesRegeneratedAtUtc = null;
        this.LastAcceptedTimeStep = null;
        this.Touch();
        return Result.Success();
    }

    public bool IsPendingAt(DateTimeOffset nowUtc) =>
        !this.IsActive &&
        this.DisabledAtUtc is null &&
        this.ProtectedSecret is not null &&
        this.EnrollmentExpiresAtUtc > nowUtc;

    public Result Activate(
        long acceptedTimeStep,
        IReadOnlyCollection<TotpRecoveryCodeRegistration> recoveryCodeRegistrations,
        DateTimeOffset nowUtc)
    {
        if (!this.IsPendingAt(nowUtc) || acceptedTimeStep < 0)
        {
            return Result.Failure(AuthDomainErrors.TotpEnrollmentInvalid);
        }

        Result replaceCodes = this.ReplaceRecoveryCodes(recoveryCodeRegistrations, nowUtc);
        if (replaceCodes.IsFailure)
        {
            return replaceCodes;
        }

        this.LastAcceptedTimeStep = acceptedTimeStep;
        this.ActivatedAtUtc = nowUtc;
        this.RecoveryCodesRegeneratedAtUtc = nowUtc;
        this.Touch();
        return Result.Success();
    }

    public Result AcceptTotp(long matchedTimeStep)
    {
        if (!this.IsActive || matchedTimeStep < 0 ||
            (this.LastAcceptedTimeStep is not null && matchedTimeStep <= this.LastAcceptedTimeStep))
        {
            return Result.Failure(AuthDomainErrors.TotpCodeInvalid);
        }

        this.LastAcceptedTimeStep = matchedTimeStep;
        this.Touch();
        return Result.Success();
    }

    public Result ConsumeRecoveryCode(
        IReadOnlyCollection<string> candidateHashes,
        DateTimeOffset nowUtc)
    {
        if (!this.IsActive || candidateHashes.Count == 0)
        {
            return Result.Failure(AuthDomainErrors.TotpCodeInvalid);
        }

        MemberTotpRecoveryCode? recoveryCode = this.recoveryCodes.FirstOrDefault(
            code => code.MatchesAny(candidateHashes));
        if (recoveryCode is null)
        {
            return Result.Failure(AuthDomainErrors.TotpCodeInvalid);
        }

        recoveryCode.Consume(nowUtc);
        this.Touch();
        return Result.Success();
    }

    public Result RegenerateRecoveryCodes(
        IReadOnlyCollection<TotpRecoveryCodeRegistration> recoveryCodeRegistrations,
        DateTimeOffset nowUtc)
    {
        if (!this.IsActive)
        {
            return Result.Failure(AuthDomainErrors.TotpAuthenticatorNotActive);
        }

        Result replaceCodes = this.ReplaceRecoveryCodes(recoveryCodeRegistrations, nowUtc);
        if (replaceCodes.IsFailure)
        {
            return replaceCodes;
        }

        this.RecoveryCodesRegeneratedAtUtc = nowUtc;
        this.Touch();
        return Result.Success();
    }

    public Result Disable(DateTimeOffset nowUtc)
    {
        if (!this.IsActive)
        {
            return Result.Failure(AuthDomainErrors.TotpAuthenticatorNotActive);
        }

        foreach (MemberTotpRecoveryCode recoveryCode in this.recoveryCodes)
        {
            recoveryCode.Revoke(nowUtc);
        }

        this.ProtectedSecret = null;
        this.DisabledAtUtc = nowUtc;
        this.Touch();
        return Result.Success();
    }

    public Result ResetByAdministrator(
        string reason,
        string actorId,
        Guid resetEventId,
        DateTimeOffset nowUtc)
    {
        bool canReset = this.IsActive || this.IsPendingAt(nowUtc);
        if (!canReset)
        {
            return Result.Failure(AuthDomainErrors.TotpAuthenticatorNotActive);
        }

        if (!TryNormalizeRequiredText(reason, AdministrativeResetReasonMaxLength, out string? normalizedReason))
        {
            return Result.Failure(AuthDomainErrors.MultiFactorResetReasonInvalid);
        }

        if (!TryNormalizeRequiredText(actorId, AdministrativeActorIdMaxLength, out string? normalizedActorId))
        {
            return Result.Failure(AuthDomainErrors.MultiFactorResetActorInvalid);
        }

        if (resetEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        foreach (MemberTotpRecoveryCode recoveryCode in this.recoveryCodes)
        {
            recoveryCode.Revoke(nowUtc);
        }

        this.ProtectedSecret = null;
        this.DisabledAtUtc = nowUtc;
        this.Touch();
        this.RaiseDomainEvent(new MemberMultiFactorAuthenticationResetDomainEvent(
            resetEventId,
            nowUtc,
            this.MemberId,
            this.ScopeId,
            normalizedActorId,
            normalizedReason));
        return Result.Success();
    }

    private Result ReplaceRecoveryCodes(
        IReadOnlyCollection<TotpRecoveryCodeRegistration> registrations,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(registrations);
        if (registrations.Count == 0 || registrations.Count > RecoveryCodeLimit ||
            registrations.Select(item => item.Id).Distinct().Count() != registrations.Count ||
            registrations.Select(item => item.Hash).Distinct(StringComparer.Ordinal).Count() != registrations.Count)
        {
            return Result.Failure(AuthDomainErrors.TotpRecoveryCodesInvalid);
        }

        List<MemberTotpRecoveryCode> replacements = [];
        foreach (TotpRecoveryCodeRegistration registration in registrations)
        {
            Result<MemberTotpRecoveryCode> created = MemberTotpRecoveryCode.Create(
                registration.Id,
                this.Id,
                this.MemberId,
                this.ScopeId,
                registration.Hash,
                nowUtc);
            if (created.IsFailure)
            {
                return Result.Failure(created.Error);
            }

            replacements.Add(created.Value);
        }

        foreach (MemberTotpRecoveryCode existing in this.recoveryCodes)
        {
            existing.Revoke(nowUtc);
        }

        this.recoveryCodes.AddRange(replacements);
        return Result.Success();
    }

    private void Touch() => this.ConcurrencyStamp = Guid.CreateVersion7();

    private static bool TryNormalizeProtectedSecret(
        string? value,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? normalized)
    {
        normalized = value?.Trim();
        return !string.IsNullOrWhiteSpace(normalized) &&
               normalized.Length <= ProtectedSecretMaxLength &&
               !normalized.Any(char.IsControl);
    }

    private static bool TryNormalizeRequiredText(
        string? value,
        int maximumLength,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? normalized)
    {
        normalized = value?.Trim();
        return !string.IsNullOrWhiteSpace(normalized) &&
               normalized.Length <= maximumLength &&
               !normalized.Any(char.IsControl);
    }
}
