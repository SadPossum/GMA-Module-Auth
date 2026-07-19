namespace Gma.Modules.Auth.Domain.Aggregates;

using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed class MemberMultiFactorFailureAttempt : ScopedAggregateRoot<MemberMultiFactorFailureAttemptId>
{
    public const int PurposeMaxLength = 64;
    public const string ManagementPurpose = "management";

    private MemberMultiFactorFailureAttempt() { }

    private MemberMultiFactorFailureAttempt(
        MemberMultiFactorFailureAttemptId id,
        MemberId memberId,
        string scopeId,
        string purpose,
        DateTimeOffset failedAtUtc)
        : base(id, scopeId)
    {
        this.MemberId = memberId;
        this.Purpose = purpose;
        this.FailedAtUtc = failedAtUtc;
    }

    public MemberId MemberId { get; private set; }
    public string Purpose { get; private set; } = string.Empty;
    public DateTimeOffset FailedAtUtc { get; private set; }

    public static Result<MemberMultiFactorFailureAttempt> Create(
        MemberMultiFactorFailureAttemptId id,
        MemberId memberId,
        string scopeId,
        string purpose,
        DateTimeOffset failedAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<MemberMultiFactorFailureAttempt>(
                AuthDomainErrors.MultiFactorFailureAttemptIdRequired);
        }

        string normalizedPurpose = purpose?.Trim().ToLowerInvariant() ?? string.Empty;
        if (memberId.Value == Guid.Empty ||
            !ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) ||
            string.IsNullOrWhiteSpace(normalizedPurpose) ||
            normalizedPurpose.Length > PurposeMaxLength ||
            normalizedPurpose.Any(char.IsControl) ||
            failedAtUtc == default)
        {
            return Result.Failure<MemberMultiFactorFailureAttempt>(AuthDomainErrors.MultiFactorFailureAttemptInvalid);
        }

        return Result.Success(new MemberMultiFactorFailureAttempt(
            id,
            memberId,
            normalizedScopeId,
            normalizedPurpose,
            failedAtUtc));
    }
}
