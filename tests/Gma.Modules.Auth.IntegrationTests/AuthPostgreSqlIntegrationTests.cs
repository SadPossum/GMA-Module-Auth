namespace Gma.Modules.Auth.IntegrationTests;

using System.Security.Cryptography;
using System.Text;
using Gma.Framework.Application.Events.Infrastructure;
using Gma.Framework.Cqrs;
using Gma.Framework.Cqrs.Infrastructure;
using Gma.Framework.Messaging.Infrastructure;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Handlers;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.IntegrationTests.Support;
using Gma.Modules.Auth.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Testcontainers.MsSql;
using Testcontainers.PostgreSql;
using Xunit;

[Trait("Category", "Docker")]
[Trait("Category", "Integration")]
public sealed class AuthPostgreSqlIntegrationTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [DockerFact]
    public async Task PostgreSql_caps_credential_attempts_across_replicas()
    {
        await using PostgreSqlContainer postgreSql = new PostgreSqlBuilder("postgres:16-alpine")
            .WithDatabase("auth_attempt_tests")
            .Build();
        await postgreSql.StartAsync();

        await RunAttemptLimiterScenarioAsync("PostgreSql", postgreSql.GetConnectionString());
    }

    [DockerFact]
    public async Task SqlServer_caps_credential_attempts_across_replicas()
    {
        await using MsSqlContainer sqlServer = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest").Build();
        await sqlServer.StartAsync();

        await RunAttemptLimiterScenarioAsync("SqlServer", sqlServer.GetConnectionString());
    }

    private static async Task RunAttemptLimiterScenarioAsync(string providerName, string connectionString)
    {
        await using ServiceProvider firstProvider = CreateProvider(providerName, connectionString);
        await using ServiceProvider secondProvider = CreateProvider(providerName, connectionString);
        await AssertAbsoluteSessionLifetimeMigrationAsync(providerName, firstProvider);
        await using AsyncServiceScope firstScope = firstProvider.CreateAsyncScope();
        await using AsyncServiceScope secondScope = secondProvider.CreateAsyncScope();
        IAuthenticationAttemptLimiter first = firstScope.ServiceProvider
            .GetRequiredService<IAuthenticationAttemptLimiter>();
        IAuthenticationAttemptLimiter second = secondScope.ServiceProvider
            .GetRequiredService<IAuthenticationAttemptLimiter>();
        AuthenticationAttemptPolicy policy = new(2, TimeSpan.FromMinutes(15));

        AuthenticationAttemptLease?[] leases = await Task.WhenAll(
            Enumerable.Range(0, 16).Select(index =>
                (index % 2 == 0 ? first : second).TryAcquireAsync(
                    "global",
                    "password-login",
                    index % 2 == 0 ? "member@example.com" : "MEMBER@example.com",
                    Now.AddTicks(index),
                    policy,
                    CancellationToken.None).AsTask()));

        AuthenticationAttemptLease[] acquired = [.. leases.OfType<AuthenticationAttemptLease>()];
        Assert.Equal(2, acquired.Length);
        Assert.Null(await first.TryAcquireAsync(
            "global", "password-login", "member@example.com", Now.AddSeconds(2), policy, CancellationToken.None));
        Assert.NotNull(await second.TryAcquireAsync(
            "global", "password-step-up", "member@example.com", Now.AddSeconds(2), policy, CancellationToken.None));

        IReadOnlyList<StoredAttempt> attempts = await ReadAttemptsAsync(firstProvider);
        Assert.Equal(3, attempts.Count);
        Assert.All(attempts, attempt =>
        {
            Assert.Equal("global", attempt.ScopeId);
            Assert.DoesNotContain("member@example.com", attempt.TargetHash, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith("test-hash:", attempt.TargetHash, StringComparison.Ordinal);
        });

        AuthenticationAttemptLease successfulLease = acquired.MaxBy(lease => lease.AcquiredAtUtc);
        await second.RecordSuccessAsync(
            "global", "password-login", "member@example.com", successfulLease, CancellationToken.None);

        Assert.NotNull(await first.TryAcquireAsync(
            "global", "password-login", "member@example.com", Now.AddSeconds(3), policy, CancellationToken.None));
        Assert.Single(
            await ReadAttemptsAsync(firstProvider),
            attempt => attempt.Purpose == "password-step-up");

        await AssertUniqueViolationClassificationAsync(firstProvider);
        await AssertDispatcherOwnsSerializationTransactionAsync(firstProvider);
        await AssertPasswordRecoveryRequestSerializationAsync(firstProvider, secondProvider);
        await AssertAuthenticationChallengeSerializationAsync(firstProvider, secondProvider);
    }

    [DockerFact]
    public async Task Session_hot_state_and_credential_retention_are_bounded_on_postgresql()
    {
        await using PostgreSqlContainer postgreSql = new PostgreSqlBuilder("postgres:16-alpine")
            .WithDatabase("auth_bounded_state_tests")
            .Build();
        await postgreSql.StartAsync();
        await using ServiceProvider provider = CreateProvider("PostgreSql", postgreSql.GetConnectionString());
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

    private static ServiceProvider CreateProvider(string providerName, string connectionString)
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(
        [
            new("Auth:FailedLoginLimit", "2"),
            new("Auth:FailedLoginWindowMinutes", "15"),
            new("Persistence:Provider", providerName),
            new($"ConnectionStrings:{providerName}", connectionString),
        ]);
        AuthProfile profile = AuthProfile.Global("global");
        builder.AddCqrsInfrastructure();
        builder.AddApplicationEventsInfrastructure();
        builder.AddMessagingInfrastructure();
        builder.Services.AddAuthApplication(builder.Configuration, profile);
        builder.Services.AddSingleton<IRefreshTokenHashingService, TestHashingService>();
        builder.Services.AddSingleton<IPasswordRecoveryTokenService, ConcurrentRecoveryTokenService>();
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

    private static async Task AssertAbsoluteSessionLifetimeMigrationAsync(
        string providerName,
        ServiceProvider provider)
    {
        string previousMigration = providerName switch
        {
            "PostgreSql" => "20260719135233_AddDurableAuthenticationAttemptLimiting",
            "SqlServer" => "20260719135243_AddDurableAuthenticationAttemptLimiting",
            _ => throw new ArgumentOutOfRangeException(nameof(providerName), providerName, "Provider is not supported."),
        };
        Guid memberId = Guid.NewGuid();
        Guid sessionId = Guid.NewGuid();
        DateTimeOffset loginAtUtc = Now.AddDays(-1);
        DateTimeOffset refreshExpiresAtUtc = Now.AddDays(7);

        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        IMigrator migrator = dbContext.Database.GetService<IMigrator>();
        await migrator.MigrateAsync(previousMigration);

        FormattableString memberInsert;
        FormattableString sessionInsert;
        if (providerName == "PostgreSql")
        {
            memberInsert = $"""
                INSERT INTO auth.members
                    ("Id", "ScopeId", "PasswordHash", "ConcurrencyStamp", "RegisteredAtUtc", "Status")
                VALUES
                    ({memberId}, {"global"}, {"password-hash"}, {Guid.NewGuid()}, {loginAtUtc}, {1});
                """;
            sessionInsert = $"""
                INSERT INTO auth.member_sessions
                    ("Id", "MemberId", "ScopeId", "RefreshTokenHash", "RefreshTokenExpiresAtUtc",
                     "LoginDateTimeUtc", "IsActive", "AuthenticationMethod", "AuthenticationContextReference",
                     authentication_method_references, "AuthenticatedAtUtc")
                VALUES
                    ({sessionId}, {memberId}, {"global"}, {"legacy-refresh-hash"}, {refreshExpiresAtUtc},
                     {loginAtUtc}, {true}, {"password"}, {AuthenticationContextReferences.Password},
                     {"[\"pwd\"]"}, {loginAtUtc});
                """;
        }
        else
        {
            memberInsert = $"""
                INSERT INTO [auth].[members]
                    ([Id], [ScopeId], [PasswordHash], [ConcurrencyStamp], [RegisteredAtUtc], [Status])
                VALUES
                    ({memberId}, {"global"}, {"password-hash"}, {Guid.NewGuid()}, {loginAtUtc}, {1});
                """;
            sessionInsert = $"""
                INSERT INTO [auth].[member_sessions]
                    ([Id], [MemberId], [ScopeId], [RefreshTokenHash], [RefreshTokenExpiresAtUtc],
                     [LoginDateTimeUtc], [IsActive], [AuthenticationMethod], [AuthenticationContextReference],
                     [authentication_method_references], [AuthenticatedAtUtc])
                VALUES
                    ({sessionId}, {memberId}, {"global"}, {"legacy-refresh-hash"}, {refreshExpiresAtUtc},
                     {loginAtUtc}, {true}, {"password"}, {AuthenticationContextReferences.Password},
                     {"[\"pwd\"]"}, {loginAtUtc});
                """;
        }
        await dbContext.Database.ExecuteSqlInterpolatedAsync(memberInsert);
        await dbContext.Database.ExecuteSqlInterpolatedAsync(sessionInsert);

        await migrator.MigrateAsync();
        dbContext.ChangeTracker.Clear();

        MemberSession migrated = await dbContext.MemberSessions
            .AsNoTracking()
            .SingleAsync(session => session.Id == new MemberSessionId(sessionId));
        Assert.Equal(refreshExpiresAtUtc, migrated.AbsoluteExpiresAtUtc);
    }

    private static async Task<IReadOnlyList<StoredAttempt>> ReadAttemptsAsync(ServiceProvider provider)
    {
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        return await dbContext.AuthenticationFailureAttempts
            .AsNoTracking()
            .OrderBy(attempt => attempt.FailedAtUtc)
            .Select(attempt => new StoredAttempt(attempt.ScopeId, attempt.Purpose, attempt.TargetHash))
            .ToArrayAsync();
    }

    private static async Task AssertUniqueViolationClassificationAsync(ServiceProvider provider)
    {
        Guid duplicateId = Guid.NewGuid();
        await using (AsyncServiceScope firstScope = provider.CreateAsyncScope())
        {
            AuthDbContext dbContext = firstScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            dbContext.AuthenticationFailureAttempts.Add(CreateAttempt(
                duplicateId,
                Now.AddMinutes(1),
                "unique-classifier-a"));
            await dbContext.SaveChangesAsync();
        }

        await using AsyncServiceScope secondScope = provider.CreateAsyncScope();
        AuthDbContext secondContext = secondScope.ServiceProvider.GetRequiredService<AuthDbContext>();
        secondContext.AuthenticationFailureAttempts.Add(CreateAttempt(
            duplicateId,
            Now.AddMinutes(2),
            "unique-classifier-b"));
        DbUpdateException exception = await Assert.ThrowsAsync<DbUpdateException>(() =>
            secondContext.SaveChangesAsync());

        Assert.True(EfDatabaseExceptionClassifier.IsUniqueConstraintViolation(exception));
    }

    private static async Task AssertDispatcherOwnsSerializationTransactionAsync(ServiceProvider provider)
    {
        const string emailAddress = "dispatch-recovery@example.com";
        Member member = Member.Create(
            new MemberId(Guid.NewGuid()),
            "global",
            emailAddress,
            MemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            Now).Value;
        MemberUsername email = Assert.Single(member.Usernames);
        Assert.True(member.RequestEmailVerification(
            email.Id,
            "dispatch-verification-hash",
            "dispatch-verification-code",
            Guid.NewGuid(),
            Now.AddHours(1),
            Now).IsSuccess);
        Assert.True(member.ConfirmEmailVerification(
            email.Id,
            "dispatch-verification-hash",
            Guid.NewGuid(),
            Now.AddMinutes(1)).IsSuccess);
        member.ClearDomainEvents();

        await using (AsyncServiceScope seedScope = provider.CreateAsyncScope())
        {
            AuthDbContext dbContext = seedScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            dbContext.Members.Add(member);
            await dbContext.SaveChangesAsync();
        }

        await using (AsyncServiceScope commandScope = provider.CreateAsyncScope())
        {
            IRequestDispatcher dispatcher = commandScope.ServiceProvider.GetRequiredService<IRequestDispatcher>();
            Result<Unit> result = await dispatcher.SendAsync(
                new RequestPasswordRecoveryCommand(emailAddress),
                CancellationToken.None);
            Assert.True(result.IsSuccess);
        }

        await using AsyncServiceScope readScope = provider.CreateAsyncScope();
        AuthDbContext readContext = readScope.ServiceProvider.GetRequiredService<AuthDbContext>();
        PasswordRecoveryChallenge challenge = Assert.Single(
            await readContext.PasswordRecoveryChallenges
                .Where(candidate => candidate.MemberId == member.Id)
                .ToArrayAsync());
        Assert.True(challenge.IsActiveAt(Now));
        Assert.Single(await readContext.OutboxMessages.AsNoTracking().ToArrayAsync());
    }

    private static async Task AssertPasswordRecoveryRequestSerializationAsync(
        ServiceProvider firstProvider,
        ServiceProvider secondProvider)
    {
        Member member = Member.Create(
            new MemberId(Guid.NewGuid()),
            "global",
            "recovery@example.com",
            MemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            Now).Value;
        MemberUsername email = Assert.Single(member.Usernames);
        Assert.True(member.RequestEmailVerification(
            email.Id,
            "verification-hash",
            "verification-code",
            Guid.NewGuid(),
            Now.AddHours(1),
            Now).IsSuccess);
        Assert.True(member.ConfirmEmailVerification(
            email.Id,
            "verification-hash",
            Guid.NewGuid(),
            Now.AddMinutes(1)).IsSuccess);
        member.ClearDomainEvents();
        await using (AsyncServiceScope seedScope = firstProvider.CreateAsyncScope())
        {
            AuthDbContext dbContext = seedScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            dbContext.Members.Add(member);
            await dbContext.SaveChangesAsync();
        }

        var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int readyCount = 0;
        var tokenService = new ConcurrentRecoveryTokenService();
        var idGenerator = new ConcurrentIdGenerator();
        Task<Result<Unit>> first = RequestAsync(firstProvider);
        Task<Result<Unit>> second = RequestAsync(secondProvider);
        Result<Unit>[] results = await Task.WhenAll(first, second);

        Assert.All(results, result => Assert.True(result.IsSuccess));
        await using AsyncServiceScope readScope = firstProvider.CreateAsyncScope();
        AuthDbContext readContext = readScope.ServiceProvider.GetRequiredService<AuthDbContext>();
        PasswordRecoveryChallenge challenge = Assert.Single(
            await readContext.PasswordRecoveryChallenges
                .Where(candidate => candidate.MemberId == member.Id)
                .ToArrayAsync());
        Assert.True(challenge.IsActiveAt(Now));

        async Task<Result<Unit>> RequestAsync(ServiceProvider provider)
        {
            await using AsyncServiceScope scope = provider.CreateAsyncScope();
            AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await using var transaction = await dbContext.Database.BeginTransactionAsync();
            if (Interlocked.Increment(ref readyCount) == 2)
            {
                ready.SetResult(true);
            }

            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var handler = new RequestPasswordRecoveryCommandHandler(
                scope.ServiceProvider.GetRequiredService<IPasswordRecoveryRecipientReader>(),
                scope.ServiceProvider.GetRequiredService<IPasswordRecoveryChallengeRepository>(),
                scope.ServiceProvider.GetRequiredService<IPasswordRecoveryRequestSerializer>(),
                tokenService,
                new FixedClock(),
                idGenerator,
                Options.Create(new AuthApplicationOptions()));
            Result<Unit> result = await handler.HandleAsync(
                new RequestPasswordRecoveryCommand("recovery@example.com"),
                CancellationToken.None);
            await dbContext.SaveChangesAsync();
            await transaction.CommitAsync();
            return result;
        }
    }

    private static async Task AssertAuthenticationChallengeSerializationAsync(
        ServiceProvider firstProvider,
        ServiceProvider secondProvider)
    {
        Member member = Member.Create(
            new MemberId(Guid.NewGuid()),
            "global",
            "multi-factor@example.com",
            MemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            Now).Value;
        await using (AsyncServiceScope seedScope = firstProvider.CreateAsyncScope())
        {
            AuthDbContext dbContext = seedScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            dbContext.Members.Add(member);
            await dbContext.SaveChangesAsync();
        }

        var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int readyCount = 0;
        int tokenSequence = 0;
        Task first = ReplaceActiveChallengeAsync(firstProvider);
        Task second = ReplaceActiveChallengeAsync(secondProvider);
        await Task.WhenAll(first, second);

        await using AsyncServiceScope readScope = firstProvider.CreateAsyncScope();
        AuthDbContext readContext = readScope.ServiceProvider.GetRequiredService<AuthDbContext>();
        MemberAuthenticationChallenge[] challenges = await readContext.MemberAuthenticationChallenges
            .Where(challenge => challenge.MemberId == member.Id)
            .ToArrayAsync();
        Assert.Equal(2, challenges.Length);
        Assert.Single(challenges, challenge => challenge.IsActiveAt(Now));

        async Task ReplaceActiveChallengeAsync(ServiceProvider provider)
        {
            await using AsyncServiceScope scope = provider.CreateAsyncScope();
            AuthDbContext dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await using var transaction = await dbContext.Database.BeginTransactionAsync();
            if (Interlocked.Increment(ref readyCount) == 2)
            {
                ready.SetResult(true);
            }

            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await scope.ServiceProvider.GetRequiredService<IAuthenticationChallengeRequestSerializer>()
                .AcquireAsync(member.ScopeId, member.Id, CancellationToken.None);
            IMemberAuthenticationChallengeRepository repository = scope.ServiceProvider
                .GetRequiredService<IMemberAuthenticationChallengeRepository>();
            IReadOnlyList<MemberAuthenticationChallenge> active = await repository
                .GetActiveByMemberAsync(member.Id, Now, CancellationToken.None);
            foreach (MemberAuthenticationChallenge challenge in active)
            {
                challenge.Revoke(Now);
            }

            int sequence = Interlocked.Increment(ref tokenSequence);
            MemberAuthenticationChallenge replacement = MemberAuthenticationChallenge.Create(
                new MemberAuthenticationChallengeId(Guid.CreateVersion7()),
                member.Id,
                member.ScopeId,
                $"challenge-hash-{sequence}",
                MemberAuthenticationMethods.Password,
                SessionAuthenticationEvidence.Password(Now),
                ipAddress: null,
                userAgent: null,
                maximumAttempts: 5,
                Now.AddMinutes(5),
                Now).Value;
            await repository.AddAsync(replacement, CancellationToken.None);
            await dbContext.SaveChangesAsync();
            await transaction.CommitAsync();
        }
    }

    private sealed class TestHashingService : IRefreshTokenHashingService
    {
        public string HashRefreshToken(string refreshToken) =>
            $"test-hash:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)))}";

        public IReadOnlyList<string> GetCandidateHashes(string refreshToken) =>
            [this.HashRefreshToken(refreshToken)];
    }

    private sealed class ConcurrentRecoveryTokenService : IPasswordRecoveryTokenService
    {
        private readonly string prefix = Guid.NewGuid().ToString("N");
        private int sequence;

        public string GenerateCode() =>
            $"recovery-code-{this.prefix}-{Interlocked.Increment(ref this.sequence)}";

        public string HashCode(string code) => $"recovery-hash:{code}";

        public IReadOnlyList<string> GetCandidateHashes(string code) => [this.HashCode(code)];
    }

    private sealed class ConcurrentIdGenerator : IIdGenerator
    {
        public Guid NewId() => Guid.CreateVersion7();
    }

    private static AuthenticationAttemptRecord CreateAttempt(DateTimeOffset failedAtUtc, string targetHash) =>
        CreateAttempt(Guid.NewGuid(), failedAtUtc, targetHash);

    private static AuthenticationAttemptRecord CreateAttempt(
        Guid id,
        DateTimeOffset failedAtUtc,
        string targetHash) =>
        new()
        {
            Id = id,
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
