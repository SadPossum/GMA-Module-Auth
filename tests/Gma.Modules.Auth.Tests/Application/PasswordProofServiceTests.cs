namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Observability;
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
    public async Task Missing_password_hash_performs_password_work_and_retains_the_attempt()
    {
        var hashingService = new RecordingPasswordHashingService();
        var limiter = new RecordingAttemptLimiter();
        var service = CreateService(hashingService, limiter);

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
        Assert.Equal(1, limiter.AcquisitionCount);
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
        var service = CreateService(hashingService, limiter);

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
        Assert.Equal(1, limiter.AcquisitionCount);
        Assert.Equal(1, limiter.SuccessCount);
    }

    [Fact]
    public async Task Exhausted_password_bucket_emits_one_payload_free_security_signal()
    {
        var hashingService = new RecordingPasswordHashingService();
        var limiter = new RecordingAttemptLimiter { RejectAcquisition = true };
        var signals = new RecordingSecuritySignalRecorder();
        var service = CreateService(hashingService, limiter, signals);

        PasswordVerificationOutcome outcome = await service.VerifyAsync(
            "tenant-a",
            AuthenticationAttemptPurposes.PasswordLogin,
            "sensitive-user@example.com",
            "password-hash",
            "candidate-password",
            Now,
            CancellationToken.None);

        Assert.Equal(PasswordVerificationOutcome.Unknown, outcome);
        SecuritySignalDefinition signal = Assert.Single(signals.Definitions);
        Assert.Equal("auth.password-proof-rate-limited", signal.Code);
        Assert.Equal(SecuritySignalCategory.Authentication, signal.Category);
        Assert.Null(hashingService.VerifiedHash);
    }

    [Fact]
    public async Task Process_local_fallback_partitions_failures_and_expires_the_window()
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter();
        AuthenticationAttemptPolicy policy = new(2, TimeSpan.FromMinutes(15));

        Assert.NotNull(await AcquireAsync(limiter, "tenant-a", "login", "member@example.com", Now, policy));
        Assert.NotNull(await AcquireAsync(limiter, "tenant-a", "login", "MEMBER@example.com", Now, policy));

        Assert.Null(await AcquireAsync(limiter, "tenant-a", "login", "member@example.com", Now, policy));
        Assert.NotNull(await AcquireAsync(limiter, "tenant-a", "step-up", "member@example.com", Now, policy));
        Assert.NotNull(await AcquireAsync(limiter, "tenant-b", "login", "member@example.com", Now, policy));
        Assert.NotNull(await AcquireAsync(limiter, "tenant-a", "login", "other@example.com", Now, policy));
        Assert.NotNull(await AcquireAsync(
            limiter, "tenant-a", "login", "member@example.com", Now.AddMinutes(15), policy));
    }

    [Fact]
    public async Task Process_local_fallback_uses_a_bounded_sliding_window()
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter();
        AuthenticationAttemptPolicy policy = new(2, TimeSpan.FromMinutes(15));

        Assert.NotNull(await AcquireAsync(limiter, "tenant-a", "login", "member@example.com", Now, policy));
        Assert.NotNull(await AcquireAsync(
            limiter, "tenant-a", "login", "member@example.com", Now.AddMinutes(14), policy));
        Assert.NotNull(await AcquireAsync(
            limiter, "tenant-a", "login", "member@example.com", Now.AddMinutes(15), policy));

        Assert.Null(await AcquireAsync(
            limiter, "tenant-a", "login", "member@example.com", Now.AddMinutes(16), policy));
        Assert.NotNull(await AcquireAsync(
            limiter, "tenant-a", "login", "member@example.com", Now.AddMinutes(30), policy));
    }

    [Fact]
    public async Task Process_local_fallback_caps_concurrent_acquisitions_atomically()
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter();
        AuthenticationAttemptPolicy policy = new(5, TimeSpan.FromMinutes(15));

        AuthenticationAttemptLease?[] leases = await Task.WhenAll(
            Enumerable.Range(0, 32)
                .Select(_ => AcquireAsync(limiter, "tenant-a", "login", "member@example.com", Now, policy)));

        Assert.Equal(5, leases.Count(lease => lease is not null));
    }

    [Fact]
    public async Task Process_local_fallback_bounds_partitions_and_recovers_after_expiry()
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter(maximumPartitions: 2);
        AuthenticationAttemptPolicy policy = new(2, TimeSpan.FromMinutes(15));

        Assert.NotNull(await AcquireAsync(limiter, "tenant-a", "login", "first@example.com", Now, policy));
        Assert.NotNull(await AcquireAsync(limiter, "tenant-a", "login", "second@example.com", Now, policy));
        Assert.Null(await AcquireAsync(limiter, "tenant-a", "login", "third@example.com", Now, policy));
        Assert.Equal(2, limiter.PartitionCount);

        Assert.NotNull(await AcquireAsync(
            limiter,
            "tenant-a",
            "login",
            "third@example.com",
            Now.AddMinutes(15),
            policy));
        Assert.Equal(1, limiter.PartitionCount);
    }

    [Fact]
    public void Attempt_policy_rejects_unbounded_values()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new AuthenticationAttemptPolicy(AuthenticationAttemptPolicy.MaximumSupportedAttempts + 1, TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new AuthenticationAttemptPolicy(1, AuthenticationAttemptPolicy.MaximumSupportedWindow.Add(TimeSpan.FromTicks(1))));
    }

    [Theory]
    [InlineData(" ", "login", "member@example.com")]
    [InlineData("tenant-a", " ", "member@example.com")]
    [InlineData("tenant-a", "login", " ")]
    [InlineData("tenant-a", "bad\npurpose", "member@example.com")]
    public async Task Process_local_fallback_rejects_invalid_partitions(
        string scopeId,
        string purpose,
        string target)
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter();

        await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            AcquireAsync(
                limiter,
                scopeId,
                purpose,
                target,
                Now,
                new AuthenticationAttemptPolicy(1, TimeSpan.FromMinutes(1))));
    }

    [Fact]
    public async Task Successful_attempt_clears_itself_and_older_attempts_but_not_later_attempts()
    {
        var limiter = new ProcessLocalAuthenticationAttemptLimiter();
        AuthenticationAttemptPolicy policy = new(2, TimeSpan.FromMinutes(15));
        AuthenticationAttemptLease older = Assert.IsType<AuthenticationAttemptLease>(
            await AcquireAsync(limiter, "tenant-a", "login", "member@example.com", Now, policy));
        AuthenticationAttemptLease later = Assert.IsType<AuthenticationAttemptLease>(
            await AcquireAsync(limiter, "tenant-a", "login", "member@example.com", Now.AddSeconds(1), policy));

        await limiter.RecordSuccessAsync(
            "tenant-a", "login", "member@example.com", older, CancellationToken.None);

        Assert.Null(await AcquireAsync(
            limiter,
            "tenant-a",
            "login",
            "member@example.com",
            Now.AddSeconds(2),
            new AuthenticationAttemptPolicy(1, TimeSpan.FromMinutes(15))));

        await limiter.RecordSuccessAsync(
            "tenant-a", "login", "member@example.com", later, CancellationToken.None);
        Assert.NotNull(await AcquireAsync(
            limiter,
            "tenant-a",
            "login",
            "member@example.com",
            Now.AddSeconds(3),
            new AuthenticationAttemptPolicy(1, TimeSpan.FromMinutes(15))));
    }

    private static PasswordProofService CreateService(
        IPasswordHashingService hashingService,
        IAuthenticationAttemptLimiter limiter,
        ISecuritySignalRecorder? securitySignals = null) =>
        new(
            hashingService,
            limiter,
            Options.Create(new AuthApplicationOptions()),
            securitySignals ?? new RecordingSecuritySignalRecorder());

    private static async Task<AuthenticationAttemptLease?> AcquireAsync(
        ProcessLocalAuthenticationAttemptLimiter limiter,
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        AuthenticationAttemptPolicy policy) =>
        await limiter.TryAcquireAsync(
            scopeId,
            purpose,
            target,
            nowUtc,
            policy,
            CancellationToken.None);

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
        public bool RejectAcquisition { get; init; }
        public int AcquisitionCount { get; private set; }
        public int SuccessCount { get; private set; }

        public ValueTask<AuthenticationAttemptLease?> TryAcquireAsync(
            string scopeId,
            string purpose,
            string target,
            DateTimeOffset nowUtc,
            AuthenticationAttemptPolicy policy,
            CancellationToken cancellationToken)
        {
            this.AcquisitionCount++;
            return ValueTask.FromResult<AuthenticationAttemptLease?>(
                this.RejectAcquisition
                    ? null
                    : new AuthenticationAttemptLease(Guid.NewGuid(), nowUtc));
        }

        public ValueTask RecordSuccessAsync(
            string scopeId,
            string purpose,
            string target,
            AuthenticationAttemptLease lease,
            CancellationToken cancellationToken)
        {
            this.SuccessCount++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingSecuritySignalRecorder : ISecuritySignalRecorder
    {
        public List<SecuritySignalDefinition> Definitions { get; } = [];

        public SecuritySignalReceipt Record(
            SecuritySignalDefinition definition,
            Guid? correlationId = null)
        {
            this.Definitions.Add(definition);
            return new(
                SecuritySignalCorrelation.Create(correlationId),
                WasEmitted: true);
        }
    }
}
