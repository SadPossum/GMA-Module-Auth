namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Naming;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed class PersistentAuthenticationAttemptLimiter(
    IServiceScopeFactory scopeFactory,
    IRefreshTokenHashingService hashingService,
    IOptions<AuthApplicationOptions> options)
    : IAuthenticationAttemptLimiter
{
    private const string HashPurpose = "authentication-attempt.v1";

    public async ValueTask<bool> IsAllowedAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId);
        string normalizedPurpose = NormalizePurpose(purpose);
        IReadOnlyList<string> targetHashes = this.GetCandidateHashes(normalizedScopeId, normalizedPurpose, target);
        DateTimeOffset cutoffUtc = nowUtc.AddMinutes(-options.Value.FailedLoginWindowMinutes);

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        int count = await dbContext.AuthenticationFailureAttempts
            .AsNoTracking()
            .Where(attempt =>
                attempt.ScopeId == normalizedScopeId &&
                attempt.Purpose == normalizedPurpose &&
                targetHashes.Contains(attempt.TargetHash) &&
                attempt.FailedAtUtc > cutoffUtc)
            .Take(options.Value.FailedLoginLimit)
            .CountAsync(cancellationToken)
            .ConfigureAwait(false);
        return count < options.Value.FailedLoginLimit;
    }

    public async ValueTask RecordFailureAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId);
        string normalizedPurpose = NormalizePurpose(purpose);
        string targetHash = hashingService.HashRefreshToken(
            CreateHashInput(normalizedScopeId, normalizedPurpose, target));

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        dbContext.AuthenticationFailureAttempts.Add(new AuthenticationAttemptRecord
        {
            Id = Guid.CreateVersion7(),
            ScopeId = normalizedScopeId,
            Purpose = normalizedPurpose,
            TargetHash = targetHash,
            FailedAtUtc = nowUtc,
        });
        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask RecordSuccessAsync(
        string scopeId,
        string purpose,
        string target,
        CancellationToken cancellationToken)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId);
        string normalizedPurpose = NormalizePurpose(purpose);
        IReadOnlyList<string> targetHashes = this.GetCandidateHashes(normalizedScopeId, normalizedPurpose, target);

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await dbContext.AuthenticationFailureAttempts
            .Where(attempt =>
                attempt.ScopeId == normalizedScopeId &&
                attempt.Purpose == normalizedPurpose &&
                targetHashes.Contains(attempt.TargetHash))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private IReadOnlyList<string> GetCandidateHashes(string scopeId, string purpose, string target) =>
        hashingService.GetCandidateHashes(CreateHashInput(scopeId, purpose, target));

    private static string CreateHashInput(string scopeId, string purpose, string target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        string normalizedTarget = target.Trim().ToUpperInvariant();
        if (normalizedTarget.Length > 512 || normalizedTarget.Any(char.IsControl))
        {
            throw new ArgumentException("Authentication attempt target is invalid.", nameof(target));
        }

        return $"{HashPurpose}\n{scopeId}\n{purpose}\n{normalizedTarget}";
    }

    private static string NormalizePurpose(string purpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        string normalized = purpose.Trim().ToLowerInvariant();
        if (normalized.Length > AuthenticationAttemptRecord.PurposeMaxLength || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("Authentication attempt purpose is invalid.", nameof(purpose));
        }

        return normalized;
    }
}
