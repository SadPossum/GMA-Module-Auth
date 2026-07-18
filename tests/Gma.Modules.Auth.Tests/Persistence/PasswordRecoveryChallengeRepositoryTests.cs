namespace Gma.Modules.Auth.Tests.Persistence;

using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Xunit;

[Trait("Category", "Unit")]
public sealed class PasswordRecoveryChallengeRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Candidate_hash_lookup_obeys_the_active_scope()
    {
        string databaseName = $"auth-recovery-repository-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot root = new();
        await using (AuthDbContext tenantA = CreateDbContext(databaseName, root, "tenant-a"))
        {
            tenantA.PasswordRecoveryChallenges.Add(CreateChallenge("tenant-a", "hash:active"));
            await tenantA.SaveChangesAsync();

            PasswordRecoveryChallenge? match = await new PasswordRecoveryChallengeRepository(tenantA)
                .GetByTokenHashesAsync(["hash:old", "hash:active"], CancellationToken.None);

            Assert.NotNull(match);
        }

        await using AuthDbContext tenantB = CreateDbContext(databaseName, root, "tenant-b");
        PasswordRecoveryChallenge? crossScope = await new PasswordRecoveryChallengeRepository(tenantB)
            .GetByTokenHashesAsync(["hash:active"], CancellationToken.None);

        Assert.Null(crossScope);
    }

    [Fact]
    public async Task Competing_consumers_fail_closed_on_the_concurrency_stamp()
    {
        string databaseName = $"auth-recovery-concurrency-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot root = new();
        await using (AuthDbContext seed = CreateDbContext(databaseName, root, "tenant-a"))
        {
            seed.PasswordRecoveryChallenges.Add(CreateChallenge("tenant-a", "hash:active"));
            await seed.SaveChangesAsync();
        }

        await using AuthDbContext firstContext = CreateDbContext(databaseName, root, "tenant-a");
        await using AuthDbContext secondContext = CreateDbContext(databaseName, root, "tenant-a");
        PasswordRecoveryChallenge first = Assert.Single(await firstContext.PasswordRecoveryChallenges.ToListAsync());
        PasswordRecoveryChallenge second = Assert.Single(await secondContext.PasswordRecoveryChallenges.ToListAsync());

        Assert.True(first.Consume("hash:active", Now.AddMinutes(1)).IsSuccess);
        Assert.True(second.Consume("hash:active", Now.AddMinutes(1)).IsSuccess);
        await firstContext.SaveChangesAsync();

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => secondContext.SaveChangesAsync());
    }

    [Fact]
    public void Persistence_model_has_bounded_lookup_and_concurrency_shape()
    {
        using AuthDbContext dbContext = CreateDbContext(
            $"auth-recovery-model-{Guid.NewGuid():N}",
            new InMemoryDatabaseRoot(),
            "tenant-a");
        IEntityType entity = dbContext.Model.FindEntityType(typeof(PasswordRecoveryChallenge))!;

        Assert.True(entity.FindProperty(nameof(PasswordRecoveryChallenge.ConcurrencyStamp))!.IsConcurrencyToken);
        Assert.Contains(entity.GetIndexes(), index =>
            index.IsUnique &&
            index.Properties.Select(property => property.Name).SequenceEqual(
                [nameof(PasswordRecoveryChallenge.ScopeId), nameof(PasswordRecoveryChallenge.TokenHash)]));
        Assert.Contains(entity.GetIndexes(), index =>
            index.Properties.Select(property => property.Name).SequenceEqual(
                [nameof(PasswordRecoveryChallenge.ScopeId), nameof(PasswordRecoveryChallenge.MemberId), nameof(PasswordRecoveryChallenge.RequestedAtUtc)]));
    }

    private static PasswordRecoveryChallenge CreateChallenge(string scopeId, string hash) =>
        PasswordRecoveryChallenge.Create(
            new PasswordRecoveryChallengeId(Guid.NewGuid()),
            new MemberId(Guid.NewGuid()),
            scopeId,
            "member@example.com",
            hash,
            "recovery-code",
            Guid.NewGuid(),
            Now.AddMinutes(30),
            Now).Value;

    private static AuthDbContext CreateDbContext(
        string databaseName,
        InMemoryDatabaseRoot root,
        string scopeId) => new(
            new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName, root)
                .Options,
            new TestScopeContext(scopeId));

    private sealed class TestScopeContext(string scopeId) : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => scopeId;
        public bool TryRestoreScope(string? restoredScopeId) =>
            string.Equals(this.ScopeId, restoredScopeId, StringComparison.Ordinal);
    }
}
