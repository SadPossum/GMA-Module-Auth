namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Naming;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class PasswordRecoveryRequestSerializer(AuthDbContext dbContext)
    : IPasswordRecoveryRequestSerializer
{
    public Task AcquireAsync(
        string scopeId,
        MemberId memberId,
        CancellationToken cancellationToken)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId);
        if (memberId.Value == Guid.Empty)
        {
            throw new ArgumentException("Member id is required.", nameof(memberId));
        }

        return EfTransactionKeyLock.AcquireAsync(
            dbContext,
            $"auth-password-recovery.v1\n{normalizedScopeId}\n{memberId.Value:D}",
            cancellationToken);
    }
}
