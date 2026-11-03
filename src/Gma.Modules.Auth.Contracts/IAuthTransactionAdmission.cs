namespace Gma.Modules.Auth.Contracts;

using System.Data.Common;

/// <summary>Acquires Auth-owned shared admission guards in the exact borrowed local database
/// transaction. Only supported PostgreSQL ReadCommitted transactions on the configured Auth
/// database are admitted. The owner must retain that transaction through its commit/rollback.
/// No connection or transaction ownership is transferred. Missing/unsupported admission denies.</summary>
public interface IAuthTransactionAdmission
{
    ValueTask<IAuthTransactionAdmissionFence?> TryAcquireAsync(AuthTransactionAdmissionRequest request,
        DbTransaction ownerTransaction, CancellationToken cancellationToken = default);
}
