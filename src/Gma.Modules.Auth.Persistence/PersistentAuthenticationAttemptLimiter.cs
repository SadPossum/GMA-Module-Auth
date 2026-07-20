namespace Gma.Modules.Auth.Persistence;

using System.Data;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;

internal sealed class PersistentAuthenticationAttemptLimiter(
    IServiceScopeFactory scopeFactory,
    IRefreshTokenHashingService hashingService)
    : IAuthenticationAttemptLimiter
{
    private const string HashPurpose = "authentication-attempt.v1";
    private const int LockTimeoutMilliseconds = 30_000;

    public async ValueTask<AuthenticationAttemptLease?> TryAcquireAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        AuthenticationAttemptPolicy policy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        AuthenticationAttemptPartition partition = AuthenticationAttemptPartition.Create(scopeId, purpose, target);
        string hashInput = CreateHashInput(partition);
        IReadOnlyList<string> targetHashes = hashingService.GetCandidateHashes(hashInput);
        DateTimeOffset cutoffUtc = nowUtc.Subtract(policy.Window);
        AuthenticationAttemptLease lease = new(Guid.CreateVersion7(), nowUtc);

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await using IDbContextTransaction transaction = await dbContext.Database
            .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            .ConfigureAwait(false);
        await EfTransactionKeyLock.AcquireAsync(
            dbContext,
            $"auth-attempt.v1\n{hashInput}",
            TimeSpan.FromMilliseconds(LockTimeoutMilliseconds),
            cancellationToken).ConfigureAwait(false);
        int count = await dbContext.AuthenticationFailureAttempts
            .AsNoTracking()
            .Where(attempt =>
                attempt.ScopeId == partition.ScopeId &&
                attempt.Purpose == partition.Purpose &&
                targetHashes.Contains(attempt.TargetHash) &&
                attempt.FailedAtUtc > cutoffUtc)
            .Take(policy.MaximumAttempts)
            .CountAsync(cancellationToken)
            .ConfigureAwait(false);
        if (count >= policy.MaximumAttempts)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }

        dbContext.AuthenticationFailureAttempts.Add(new AuthenticationAttemptRecord
        {
            Id = lease.AttemptId,
            ScopeId = partition.ScopeId,
            Purpose = partition.Purpose,
            TargetHash = hashingService.HashRefreshToken(hashInput),
            FailedAtUtc = nowUtc,
        });
        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return lease;
    }

    public async ValueTask RecordSuccessAsync(
        string scopeId,
        string purpose,
        string target,
        AuthenticationAttemptLease lease,
        CancellationToken cancellationToken)
    {
        AuthenticationAttemptPartition partition = AuthenticationAttemptPartition.Create(scopeId, purpose, target);
        string hashInput = CreateHashInput(partition);
        IReadOnlyList<string> targetHashes = hashingService.GetCandidateHashes(hashInput);

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await using IDbContextTransaction transaction = await dbContext.Database
            .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            .ConfigureAwait(false);
        await EfTransactionKeyLock.AcquireAsync(
            dbContext,
            $"auth-attempt.v1\n{hashInput}",
            TimeSpan.FromMilliseconds(LockTimeoutMilliseconds),
            cancellationToken).ConfigureAwait(false);
        await dbContext.AuthenticationFailureAttempts
            .Where(attempt =>
                attempt.ScopeId == partition.ScopeId &&
                attempt.Purpose == partition.Purpose &&
                targetHashes.Contains(attempt.TargetHash) &&
                (attempt.FailedAtUtc < lease.AcquiredAtUtc ||
                    (attempt.FailedAtUtc == lease.AcquiredAtUtc && attempt.Id == lease.AttemptId)))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string CreateHashInput(AuthenticationAttemptPartition partition) =>
        $"{HashPurpose}\n{partition.Key}";
}
