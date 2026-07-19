namespace Gma.Modules.Auth.IntegrationTests;

using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.IntegrationTests.Support;
using Gma.Modules.Auth.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Testcontainers.PostgreSql;
using Xunit;

[Trait("Category", "Docker")]
[Trait("Category", "Integration")]
public sealed class AuthPostgreSqlIntegrationTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [DockerFact]
    public async Task Credential_failures_are_shared_hashed_and_cleared_across_replicas()
    {
        await using PostgreSqlContainer postgreSql = new PostgreSqlBuilder("postgres:16-alpine")
            .WithDatabase("auth_attempt_tests")
            .Build();
        await postgreSql.StartAsync();
        await using ServiceProvider firstProvider = CreateProvider(postgreSql.GetConnectionString());
        await using ServiceProvider secondProvider = CreateProvider(postgreSql.GetConnectionString());
        await MigrateAsync(firstProvider);
        await using AsyncServiceScope firstScope = firstProvider.CreateAsyncScope();
        await using AsyncServiceScope secondScope = secondProvider.CreateAsyncScope();
        IAuthenticationAttemptLimiter first = firstScope.ServiceProvider
            .GetRequiredService<IAuthenticationAttemptLimiter>();
        IAuthenticationAttemptLimiter second = secondScope.ServiceProvider
            .GetRequiredService<IAuthenticationAttemptLimiter>();

        await Task.WhenAll(
            first.RecordFailureAsync(
                "global", "password-login", "member@example.com", Now, CancellationToken.None).AsTask(),
            second.RecordFailureAsync(
                "global", "password-login", "MEMBER@example.com", Now.AddSeconds(1), CancellationToken.None).AsTask());

        Assert.False(await first.IsAllowedAsync(
            "global", "password-login", "member@example.com", Now.AddSeconds(2), CancellationToken.None));
        Assert.False(await second.IsAllowedAsync(
            "global", "password-login", "member@example.com", Now.AddSeconds(2), CancellationToken.None));
        Assert.True(await second.IsAllowedAsync(
            "global", "password-step-up", "member@example.com", Now.AddSeconds(2), CancellationToken.None));

        IReadOnlyList<StoredAttempt> attempts = await ReadAttemptsAsync(firstProvider);
        Assert.Equal(2, attempts.Count);
        Assert.All(attempts, attempt =>
        {
            Assert.Equal("global", attempt.ScopeId);
            Assert.Equal("password-login", attempt.Purpose);
            Assert.DoesNotContain("member@example.com", attempt.TargetHash, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith("test-hash:", attempt.TargetHash, StringComparison.Ordinal);
        });

        await second.RecordSuccessAsync(
            "global", "password-login", "member@example.com", CancellationToken.None);

        Assert.True(await first.IsAllowedAsync(
            "global", "password-login", "member@example.com", Now.AddSeconds(3), CancellationToken.None));
        Assert.Empty(await ReadAttemptsAsync(firstProvider));
    }

    [DockerFact]
    public async Task Session_hot_state_and_credential_retention_are_bounded_on_postgresql()
    {
        await using PostgreSqlContainer postgreSql = new PostgreSqlBuilder("postgres:16-alpine")
            .WithDatabase("auth_bounded_state_tests")
            .Build();
        await postgreSql.StartAsync();
        await using ServiceProvider provider = CreateProvider(postgreSql.GetConnectionString());
        await MigrateAsync(provider);
        Member member = Member.Create(
            new MemberId(Guid.NewGuid()),
            "global",
            "member@example.com",
            MemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            Now.AddDays(-2)).Value;
        member.StartSession(
            new MemberSessionId(Guid.NewGuid()), "expired-hash", Now.AddMinutes(-1), Now.AddDays(-1));
        MemberSessionId signedOutId = new(Guid.NewGuid());
        member.StartSession(signedOutId, "signed-out-hash", Now.AddDays(1), Now.AddHours(-2));
        member.SignOutSession(signedOutId, Now.AddHours(-1));
        member.StartSession(
            new MemberSessionId(Guid.Parse("00000000-0000-0000-0000-000000000001")),
            "oldest-live-hash",
            Now.AddDays(1),
            Now,
            maximumActiveSessions: 2);
        member.StartSession(
            new MemberSessionId(Guid.Parse("00000000-0000-0000-0000-000000000002")),
            "newer-live-hash",
            Now.AddDays(1),
            Now,
            maximumActiveSessions: 2);
        member.StartSession(
            new MemberSessionId(Guid.Parse("00000000-0000-0000-0000-000000000003")),
            "newest-live-hash",
            Now.AddDays(1),
            Now,
            maximumActiveSessions: 2);

        await using (AsyncServiceScope seedScope = provider.CreateAsyncScope())
        {
            AuthDbContext seed = seedScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            seed.Members.Add(member);
            seed.AuthenticationFailureAttempts.AddRange(
                CreateAttempt(Now.AddHours(-2), "old-target-hash"),
                CreateAttempt(Now.AddMinutes(-30), "recent-target-hash"));
            await seed.SaveChangesAsync();
        }

        await using (AsyncServiceScope readScope = provider.CreateAsyncScope())
        {
            IMemberRepository repository = readScope.ServiceProvider.GetRequiredService<IMemberRepository>();
            Member hydrated = Assert.IsType<Member>(await repository.GetByIdAsync(member.Id, CancellationToken.None));
            Assert.Equal(2, hydrated.Sessions.Count);
            Assert.All(hydrated.Sessions, session =>
            {
                Assert.True(session.IsActive);
                Assert.True(session.RefreshTokenExpiresAtUtc > Now);
            });
        }

        AuthRetentionService retention = new(
            provider.GetRequiredService<IServiceScopeFactory>(),
            new FixedClock(),
            Options.Create(new AuthRetentionOptions
            {
                Enabled = true,
                AuthenticationFailureHistoryHours = 1,
                BatchSize = 1,
                MaxBatchesPerCategoryPerCycle = 10,
                IntervalMinutes = 60,
            }),
            NullLogger<AuthRetentionService>.Instance);

        await retention.CleanupAsync(CancellationToken.None);

        IReadOnlyList<StoredAttempt> attempts = await ReadAttemptsAsync(provider);
        Assert.Equal("recent-target-hash", Assert.Single(attempts).TargetHash);
    }

    private static ServiceProvider CreateProvider(string connectionString)
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(
        [
            new("Auth:FailedLoginLimit", "2"),
            new("Auth:FailedLoginWindowMinutes", "15"),
            new("Persistence:Provider", "PostgreSql"),
            new("ConnectionStrings:PostgreSql", connectionString),
        ]);
        AuthProfile profile = AuthProfile.Global("global");
        builder.Services.AddAuthApplication(builder.Configuration, profile);
        builder.Services.AddSingleton<IRefreshTokenHashingService, TestHashingService>();
        builder.Services.AddSingleton<ISystemClock, FixedClock>();
        builder.AddAuthPersistence(profile);
        return builder.Services.BuildServiceProvider(validateScopes: true);
    }

    private static async Task MigrateAsync(ServiceProvider provider)
    {
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await dbContext.Database.MigrateAsync();
    }

    private static async Task<IReadOnlyList<StoredAttempt>> ReadAttemptsAsync(ServiceProvider provider)
    {
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DbConnection connection = dbContext.Database.GetDbConnection();
        await connection.OpenAsync();
        await using DbCommand command = connection.CreateCommand();
        command.CommandText = "SELECT \"ScopeId\", \"Purpose\", \"TargetHash\" FROM auth.authentication_failure_attempts ORDER BY \"FailedAtUtc\"";
        await using DbDataReader reader = await command.ExecuteReaderAsync();
        List<StoredAttempt> attempts = [];
        while (await reader.ReadAsync())
        {
            attempts.Add(new StoredAttempt(reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }

        return attempts;
    }

    private sealed class TestHashingService : IRefreshTokenHashingService
    {
        public string HashRefreshToken(string refreshToken) =>
            $"test-hash:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)))}";

        public IReadOnlyList<string> GetCandidateHashes(string refreshToken) =>
            [this.HashRefreshToken(refreshToken)];
    }

    private static AuthenticationAttemptRecord CreateAttempt(DateTimeOffset failedAtUtc, string targetHash) =>
        new()
        {
            Id = Guid.NewGuid(),
            ScopeId = "global",
            Purpose = "password-login",
            TargetHash = targetHash,
            FailedAtUtc = failedAtUtc,
        };

    private sealed class FixedClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
    }

    private sealed record StoredAttempt(string ScopeId, string Purpose, string TargetHash);
}
