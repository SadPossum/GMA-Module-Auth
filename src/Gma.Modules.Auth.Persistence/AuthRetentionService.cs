namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Runtime.Maintenance;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

internal sealed class AuthRetentionService(
    IServiceScopeFactory scopeFactory,
    ISystemClock clock,
    IOptions<AuthRetentionOptions> options,
    ILogger<AuthRetentionService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromMinutes(options.Value.IntervalMinutes));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await this.CleanupAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogError(
                    "Auth retention iteration failed with {ExceptionType}; cleanup will retry on the next interval.",
                    exception.GetType().Name);
            }

            try
            {
                await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    internal async Task CleanupAsync(CancellationToken cancellationToken)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        AuthRetentionOptions settings = options.Value;
        DateTimeOffset nowUtc = clock.UtcNow;
        DateTimeOffset exchangeCutoffUtc = nowUtc.AddHours(-settings.ExpiredExchangeHistoryHours);
        DateTimeOffset sessionCutoffUtc = nowUtc.AddDays(-settings.SessionHistoryDays);
        DateTimeOffset recoveryCutoffUtc = nowUtc.AddHours(-settings.PasswordRecoveryHistoryHours);
        DateTimeOffset authenticationChallengeCutoffUtc = nowUtc.AddHours(-settings.AuthenticationChallengeHistoryHours);
        DateTimeOffset expiredEnrollmentCutoffUtc = nowUtc.AddHours(-settings.ExpiredTotpEnrollmentHistoryHours);
        DateTimeOffset disabledAuthenticatorCutoffUtc = nowUtc.AddDays(-settings.DisabledTotpAuthenticatorHistoryDays);
        DateTimeOffset multiFactorFailureCutoffUtc = nowUtc.AddHours(-settings.MultiFactorFailureHistoryHours);
        DateTimeOffset authenticationFailureCutoffUtc = nowUtc.AddHours(-settings.AuthenticationFailureHistoryHours);
        IExternalAuthenticationExchangeStore exchangeStore = scope.ServiceProvider
            .GetRequiredService<IExternalAuthenticationExchangeStore>();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

        int exchangeCount = await BoundedBatchProcessor.ExecuteAsync(
                settings.BatchSize,
                settings.MaxBatchesPerCategoryPerCycle,
                (batchSize, token) => exchangeStore.DeleteExpiredAsync(exchangeCutoffUtc, batchSize, token),
                cancellationToken)
            .ConfigureAwait(false);
        int sessionCount = await BoundedBatchProcessor.ExecuteAsync(
                settings.BatchSize,
                settings.MaxBatchesPerCategoryPerCycle,
                (batchSize, token) => DeleteExpiredSessionsBatchAsync(
                    dbContext,
                    sessionCutoffUtc,
                    batchSize,
                    token),
                cancellationToken)
            .ConfigureAwait(false);
        int recoveryCount = await BoundedBatchProcessor.ExecuteAsync(
                settings.BatchSize,
                settings.MaxBatchesPerCategoryPerCycle,
                (batchSize, token) => DeletePasswordRecoveryChallengesBatchAsync(
                    dbContext,
                    recoveryCutoffUtc,
                    batchSize,
                    token),
                cancellationToken)
            .ConfigureAwait(false);
        int authenticationChallengeCount = await BoundedBatchProcessor.ExecuteAsync(
                settings.BatchSize,
                settings.MaxBatchesPerCategoryPerCycle,
                (batchSize, token) => DeleteAuthenticationChallengesBatchAsync(
                    dbContext,
                    authenticationChallengeCutoffUtc,
                    batchSize,
                    token),
                cancellationToken)
            .ConfigureAwait(false);
        int authenticatorCount = await BoundedBatchProcessor.ExecuteAsync(
                settings.BatchSize,
                settings.MaxBatchesPerCategoryPerCycle,
                (batchSize, token) => DeleteTotpAuthenticatorsBatchAsync(
                    dbContext,
                    expiredEnrollmentCutoffUtc,
                    disabledAuthenticatorCutoffUtc,
                    batchSize,
                    token),
                cancellationToken)
            .ConfigureAwait(false);
        int multiFactorFailureCount = await BoundedBatchProcessor.ExecuteAsync(
                settings.BatchSize,
                settings.MaxBatchesPerCategoryPerCycle,
                (batchSize, token) => DeleteMultiFactorFailuresBatchAsync(
                    dbContext,
                    multiFactorFailureCutoffUtc,
                    batchSize,
                    token),
                cancellationToken)
            .ConfigureAwait(false);
        int authenticationFailureCount = await BoundedBatchProcessor.ExecuteAsync(
                settings.BatchSize,
                settings.MaxBatchesPerCategoryPerCycle,
                (batchSize, token) => DeleteAuthenticationFailuresBatchAsync(
                    dbContext,
                    authenticationFailureCutoffUtc,
                    batchSize,
                    token),
                cancellationToken)
            .ConfigureAwait(false);

        if (exchangeCount > 0 || sessionCount > 0 || recoveryCount > 0 ||
            authenticationChallengeCount > 0 || authenticatorCount > 0 || multiFactorFailureCount > 0 ||
            authenticationFailureCount > 0)
        {
            logger.LogInformation(
                "Auth retention removed {ExchangeCount} external authentication exchanges, {SessionCount} sessions, {RecoveryCount} password recovery challenges, {AuthenticationChallengeCount} authentication challenges, {AuthenticatorCount} TOTP authenticators, {MultiFactorFailureCount} multi-factor failures, and {AuthenticationFailureCount} credential failures.",
                exchangeCount,
                sessionCount,
                recoveryCount,
                authenticationChallengeCount,
                authenticatorCount,
                multiFactorFailureCount,
                authenticationFailureCount);
        }
    }

    private static async Task<int> DeleteExpiredSessionsBatchAsync(
        AuthDbContext dbContext,
        DateTimeOffset cutoffUtc,
        int batchSize,
        CancellationToken cancellationToken)
    {
        IQueryable<MemberSession> sessions = dbContext.MemberSessions.IgnoreQueryFilters();
        List<MemberSessionId> sessionIds = await sessions
            .Where(session =>
                session.RefreshTokenExpiresAtUtc <= cutoffUtc)
            .OrderBy(session => session.RefreshTokenExpiresAtUtc)
            .Select(session => session.Id)
            .Take(batchSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        if (sessionIds.Count < batchSize)
        {
            MemberSessionId[] signedOutIds = await sessions
                .Where(session =>
                    session.RefreshTokenExpiresAtUtc > cutoffUtc &&
                    !session.IsActive &&
                    session.SignOutDateTimeUtc != null &&
                    session.SignOutDateTimeUtc <= cutoffUtc)
                .OrderBy(session => session.SignOutDateTimeUtc)
                .Select(session => session.Id)
                .Take(batchSize - sessionIds.Count)
                .ToArrayAsync(cancellationToken)
                .ConfigureAwait(false);
            sessionIds.AddRange(signedOutIds);
        }

        if (sessionIds.Count == 0)
        {
            return 0;
        }

        return await dbContext.MemberSessions
            .IgnoreQueryFilters()
            .Where(session => sessionIds.Contains(session.Id))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<int> DeletePasswordRecoveryChallengesBatchAsync(
        AuthDbContext dbContext,
        DateTimeOffset cutoffUtc,
        int batchSize,
        CancellationToken cancellationToken)
    {
        PasswordRecoveryChallengeId[] challengeIds = await dbContext.PasswordRecoveryChallenges
            .IgnoreQueryFilters()
            .Where(challenge =>
                challenge.ExpiresAtUtc <= cutoffUtc ||
                challenge.ConsumedAtUtc <= cutoffUtc ||
                challenge.RevokedAtUtc <= cutoffUtc)
            .OrderBy(challenge => challenge.ExpiresAtUtc)
            .Select(challenge => challenge.Id)
            .Take(batchSize)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);

        if (challengeIds.Length == 0)
        {
            return 0;
        }

        return await dbContext.PasswordRecoveryChallenges
            .IgnoreQueryFilters()
            .Where(challenge => challengeIds.Contains(challenge.Id))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<int> DeleteAuthenticationChallengesBatchAsync(
        AuthDbContext dbContext,
        DateTimeOffset cutoffUtc,
        int batchSize,
        CancellationToken cancellationToken)
    {
        MemberAuthenticationChallengeId[] challengeIds = await dbContext.MemberAuthenticationChallenges
            .IgnoreQueryFilters()
            .Where(challenge =>
                challenge.ExpiresAtUtc <= cutoffUtc ||
                challenge.ConsumedAtUtc <= cutoffUtc ||
                challenge.RevokedAtUtc <= cutoffUtc)
            .OrderBy(challenge => challenge.ExpiresAtUtc)
            .Select(challenge => challenge.Id)
            .Take(batchSize)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);

        if (challengeIds.Length == 0)
        {
            return 0;
        }

        return await dbContext.MemberAuthenticationChallenges
            .IgnoreQueryFilters()
            .Where(challenge => challengeIds.Contains(challenge.Id))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<int> DeleteTotpAuthenticatorsBatchAsync(
        AuthDbContext dbContext,
        DateTimeOffset expiredEnrollmentCutoffUtc,
        DateTimeOffset disabledAuthenticatorCutoffUtc,
        int batchSize,
        CancellationToken cancellationToken)
    {
        MemberTotpAuthenticatorId[] authenticatorIds = await dbContext.MemberTotpAuthenticators
            .IgnoreQueryFilters()
            .Where(authenticator =>
                (authenticator.ActivatedAtUtc == null &&
                 authenticator.DisabledAtUtc == null &&
                 authenticator.EnrollmentExpiresAtUtc <= expiredEnrollmentCutoffUtc) ||
                (authenticator.DisabledAtUtc != null &&
                 authenticator.DisabledAtUtc <= disabledAuthenticatorCutoffUtc))
            .OrderBy(authenticator => authenticator.EnrollmentExpiresAtUtc)
            .Select(authenticator => authenticator.Id)
            .Take(batchSize)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);

        if (authenticatorIds.Length == 0)
        {
            return 0;
        }

        return await dbContext.MemberTotpAuthenticators
            .IgnoreQueryFilters()
            .Where(authenticator => authenticatorIds.Contains(authenticator.Id))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<int> DeleteMultiFactorFailuresBatchAsync(
        AuthDbContext dbContext,
        DateTimeOffset cutoffUtc,
        int batchSize,
        CancellationToken cancellationToken)
    {
        MemberMultiFactorFailureAttemptId[] attemptIds = await dbContext.MemberMultiFactorFailureAttempts
            .IgnoreQueryFilters()
            .Where(attempt => attempt.FailedAtUtc <= cutoffUtc)
            .OrderBy(attempt => attempt.FailedAtUtc)
            .Select(attempt => attempt.Id)
            .Take(batchSize)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);

        if (attemptIds.Length == 0)
        {
            return 0;
        }

        return await dbContext.MemberMultiFactorFailureAttempts
            .IgnoreQueryFilters()
            .Where(attempt => attemptIds.Contains(attempt.Id))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<int> DeleteAuthenticationFailuresBatchAsync(
        AuthDbContext dbContext,
        DateTimeOffset cutoffUtc,
        int batchSize,
        CancellationToken cancellationToken)
    {
        Guid[] attemptIds = await dbContext.AuthenticationFailureAttempts
            .IgnoreQueryFilters()
            .Where(attempt => attempt.FailedAtUtc <= cutoffUtc)
            .OrderBy(attempt => attempt.FailedAtUtc)
            .Select(attempt => attempt.Id)
            .Take(batchSize)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);

        if (attemptIds.Length == 0)
        {
            return 0;
        }

        return await dbContext.AuthenticationFailureAttempts
            .IgnoreQueryFilters()
            .Where(attempt => attemptIds.Contains(attempt.Id))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }
}
