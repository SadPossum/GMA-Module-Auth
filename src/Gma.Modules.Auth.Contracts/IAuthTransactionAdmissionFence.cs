namespace Gma.Modules.Auth.Contracts;

/// <summary>Cooperating persisted invalidations serialize with this fence until owner completion.
/// Revalidate before the owner's commit; expiry and configuration are not frozen by database locks.
/// Disposal releases only the borrowed read context, never the owner's transaction or its locks.</summary>
public interface IAuthTransactionAdmissionFence : IAsyncDisposable
{
    AuthTransactionAdmissionEvidence Evidence { get; }
    ValueTask<bool> RevalidateAsync(CancellationToken cancellationToken = default);
}
