namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class PasswordProofServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Missing_password_hash_performs_password_work_and_records_failure()
    {
        var hashingService = new RecordingPasswordHashingService();
        var limiter = new RecordingAttemptLimiter();
        var service = new PasswordProofService(hashingService, limiter);

        PasswordVerificationOutcome outcome = await service.VerifyAsync(
            "tenant-a",
            AuthenticationAttemptPurposes.PasswordLogin,
            "missing@example.com",
            null,
            "candidate-password",
            Now,
            CancellationToken.None);

        Assert.Equal(PasswordVerificationOutcome.Unknown, outcome);
        Assert.Equal("candidate-password", hashingService.HashedPassword);
        Assert.Null(hashingService.VerifiedHash);
        Assert.Equal(1, limiter.FailureCount);
        Assert.Equal(0, limiter.SuccessCount);
    }

    [Fact]
    public async Task Successful_password_proof_clears_the_matching_failure_bucket()
    {
        var hashingService = new RecordingPasswordHashingService
        {
            VerificationOutcome = PasswordVerificationOutcome.Success,
        };
        var limiter = new RecordingAttemptLimiter();
        var service = new PasswordProofService(hashingService, limiter);

        PasswordVerificationOutcome outcome = await service.VerifyAsync(
            "tenant-a",
            AuthenticationAttemptPurposes.PasswordStepUp,
            "member-id",
            "password-hash",
            "candidate-password",
            Now,
            CancellationToken.None);

        Assert.Equal(PasswordVerificationOutcome.Success, outcome);
        Assert.Equal("password-hash", hashingService.VerifiedHash);
        Assert.Equal(0, limiter.FailureCount);
        Assert.Equal(1, limiter.SuccessCount);
    }

    [Fact]
    public async Task Process_local_fallback_partitions_failures_and_expires_the_window()
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter(Options.Create(new AuthApplicationOptions
        {
            FailedLoginLimit = 2,
            FailedLoginWindowMinutes = 15,
        }));

        await limiter.RecordFailureAsync("tenant-a", "login", "member@example.com", Now, CancellationToken.None);
        await limiter.RecordFailureAsync("tenant-a", "login", "MEMBER@example.com", Now, CancellationToken.None);

        Assert.False(await limiter.IsAllowedAsync(
            "tenant-a", "login", "member@example.com", Now, CancellationToken.None));
        Assert.True(await limiter.IsAllowedAsync(
            "tenant-a", "step-up", "member@example.com", Now, CancellationToken.None));
        Assert.True(await limiter.IsAllowedAsync(
            "tenant-b", "login", "member@example.com", Now, CancellationToken.None));
        Assert.True(await limiter.IsAllowedAsync(
            "tenant-a", "login", "other@example.com", Now, CancellationToken.None));
        Assert.True(await limiter.IsAllowedAsync(
            "tenant-a", "login", "member@example.com", Now.AddMinutes(15), CancellationToken.None));
    }

    [Fact]
    public async Task Process_local_fallback_uses_a_bounded_sliding_window()
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter(Options.Create(new AuthApplicationOptions
        {
            FailedLoginLimit = 2,
            FailedLoginWindowMinutes = 15,
        }));

        await limiter.RecordFailureAsync(
            "tenant-a", "login", "member@example.com", Now, CancellationToken.None);
        await limiter.RecordFailureAsync(
            "tenant-a", "login", "member@example.com", Now.AddMinutes(14), CancellationToken.None);
        Assert.True(await limiter.IsAllowedAsync(
            "tenant-a", "login", "member@example.com", Now.AddMinutes(15), CancellationToken.None));

        await limiter.RecordFailureAsync(
            "tenant-a", "login", "member@example.com", Now.AddMinutes(15), CancellationToken.None);

        Assert.False(await limiter.IsAllowedAsync(
            "tenant-a", "login", "member@example.com", Now.AddMinutes(16), CancellationToken.None));
        Assert.True(await limiter.IsAllowedAsync(
            "tenant-a", "login", "member@example.com", Now.AddMinutes(30), CancellationToken.None));
    }

    private sealed class RecordingPasswordHashingService : IPasswordHashingService
    {
        public PasswordVerificationOutcome VerificationOutcome { get; init; } = PasswordVerificationOutcome.Unknown;
        public string? HashedPassword { get; private set; }
        public string? VerifiedHash { get; private set; }

        public string HashPassword(string password)
        {
            this.HashedPassword = password;
            return "dummy-hash";
        }

        public PasswordVerificationOutcome VerifyPassword(string passwordHash, string password)
        {
            this.VerifiedHash = passwordHash;
            return this.VerificationOutcome;
        }
    }

    private sealed class RecordingAttemptLimiter : IAuthenticationAttemptLimiter
    {
        public int FailureCount { get; private set; }
        public int SuccessCount { get; private set; }

        public ValueTask<bool> IsAllowedAsync(
            string scopeId,
            string purpose,
            string target,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken) => ValueTask.FromResult(true);

        public ValueTask RecordFailureAsync(
            string scopeId,
            string purpose,
            string target,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken)
        {
            this.FailureCount++;
            return ValueTask.CompletedTask;
        }

        public ValueTask RecordSuccessAsync(
            string scopeId,
            string purpose,
            string target,
            CancellationToken cancellationToken)
        {
            this.SuccessCount++;
            return ValueTask.CompletedTask;
        }
    }
}
