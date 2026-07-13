namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Xunit;

[Trait("Category", "Unit")]
public sealed class ExternalAuthenticationExchangeStoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Consume_is_committed_with_the_unit_of_work_instead_of_burning_on_failure()
    {
        string databaseName = $"auth-exchange-rollback-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot root = new();
        await SeedAsync(databaseName, root, "code-hash");

        await using (AuthDbContext abandonedContext = CreateDbContext(databaseName, root))
        {
            var abandonedStore = new ExternalAuthenticationExchangeStore(abandonedContext);
            Assert.NotNull(await abandonedStore.ConsumeAsync("code-hash", Now, CancellationToken.None));
        }

        await using AuthDbContext retryContext = CreateDbContext(databaseName, root);
        var retryStore = new ExternalAuthenticationExchangeStore(retryContext);
        Assert.NotNull(await retryStore.ConsumeAsync("code-hash", Now, CancellationToken.None));
        await retryContext.SaveChangesAsync();
        Assert.Null(await retryStore.ConsumeAsync("code-hash", Now, CancellationToken.None));
    }

    [Fact]
    public async Task Concurrent_consumers_have_one_concurrency_winner()
    {
        string databaseName = $"auth-exchange-concurrency-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot root = new();
        await SeedAsync(databaseName, root, "code-hash");
        await using AuthDbContext firstContext = CreateDbContext(databaseName, root);
        await using AuthDbContext secondContext = CreateDbContext(databaseName, root);
        var firstStore = new ExternalAuthenticationExchangeStore(firstContext);
        var secondStore = new ExternalAuthenticationExchangeStore(secondContext);

        Assert.NotNull(await firstStore.ConsumeAsync("code-hash", Now, CancellationToken.None));
        Assert.NotNull(await secondStore.ConsumeAsync("code-hash", Now.AddSeconds(1), CancellationToken.None));

        await firstContext.SaveChangesAsync();
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => secondContext.SaveChangesAsync());
    }

    private static async Task SeedAsync(
        string databaseName,
        InMemoryDatabaseRoot root,
        string codeHash)
    {
        await using AuthDbContext context = CreateDbContext(databaseName, root);
        var store = new ExternalAuthenticationExchangeStore(context);
        await store.AddAsync(
            new ExternalAuthenticationExchange(
                Guid.NewGuid(),
                "tenant-a",
                codeHash,
                ExternalAuthenticationIntent.SignIn,
                "google",
                "https://accounts.google.com",
                "subject",
                "member@example.com",
                EmailVerified: true,
                TargetMemberId: null,
                TargetSessionId: null,
                "/auth/complete",
                Now.AddMinutes(-1),
                Now.AddMinutes(5)),
            CancellationToken.None);
        await context.SaveChangesAsync();
    }

    private static AuthDbContext CreateDbContext(string databaseName, InMemoryDatabaseRoot root) =>
        new(
            new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName, root)
                .Options,
            new TestScopeContext());

    private sealed class TestScopeContext : IScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => "tenant-a";
    }
}
