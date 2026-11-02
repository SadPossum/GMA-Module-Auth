namespace Gma.Modules.Auth.Contracts;

using System.Data.Common;

/// <summary>Identity/session facts only; this is not financial permission, history certification,
/// or permission to act for another subject. The caller separately binds its authenticated actor.</summary>
public sealed record AuthTransactionAdmissionRequest(string ScopeId, Guid MemberId, Guid SessionId);

public sealed record AuthTransactionAdmissionEvidence(AuthTransactionAdmissionRequest Request,
    DateTimeOffset ObservedAtUtc, DateTimeOffset ValidUntilUtc);

/// <summary>Acquires Auth-owned shared admission guards in the exact borrowed local database
/// transaction. Only supported PostgreSQL ReadCommitted transactions on the configured Auth
/// database are admitted. The owner must retain that transaction through its commit/rollback.
/// No connection or transaction ownership is transferred. Missing/unsupported admission denies.</summary>
public interface IAuthTransactionAdmission
{
    ValueTask<IAuthTransactionAdmissionFence?> TryAcquireAsync(AuthTransactionAdmissionRequest request,
        DbTransaction ownerTransaction, CancellationToken cancellationToken = default);
}

/// <summary>Cooperating persisted invalidations serialize with this fence until owner completion.
/// Revalidate before the owner's commit; expiry and configuration are not frozen by database locks.
/// Disposal releases only the borrowed read context, never the owner's transaction or its locks.</summary>
public interface IAuthTransactionAdmissionFence : IAsyncDisposable
{
    AuthTransactionAdmissionEvidence Evidence { get; }
    ValueTask<bool> RevalidateAsync(CancellationToken cancellationToken = default);
}
