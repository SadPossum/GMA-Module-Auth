namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Gma.Framework.Scoping;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Xunit;

[Trait("Category", "Unit")]
public sealed class MemberRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 2, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Username_exists_reserves_inactive_username_history_while_login_uses_active_username()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        MemberRepository repository = new(dbContext);
        Member member = CreateMember("member@example.com");

        var changed = member.AddUsername(
            new MemberUsernameId(Guid.NewGuid()),
            "other@example.com",
            MemberUsernameType.Email);
        Assert.True(changed.IsSuccess);

        await repository.AddAsync(member, CancellationToken.None);
        await dbContext.SaveChangesAsync(CancellationToken.None);

        Assert.True(await repository.UsernameExistsAsync("member@example.com", CancellationToken.None));
        Assert.Null(await repository.GetByUsernameAsync("member@example.com", CancellationToken.None));
        Assert.NotNull(await repository.GetByUsernameAsync("other@example.com", CancellationToken.None));
    }

    [Fact]
    public async Task Fixed_global_scope_filters_reads_and_rejects_tenant_writes()
    {
        string databaseName = $"auth-fixed-scope-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        DbContextOptions<AuthDbContext> options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName, databaseRoot)
            .Options;

        await using (AuthDbContext seed = new(options, new TestTenantContext(scopeId: null, enabled: false)))
        {
            seed.Members.Add(CreateMember("global@example.com", "global"));
            seed.Members.Add(CreateMember("tenant@example.com", "tenant-a"));
            await seed.SaveChangesAsync(CancellationToken.None);
        }

        await using AuthDbContext global = new(options, new TestTenantContext("global"));

        Member visible = Assert.Single(await global.Members.ToListAsync(CancellationToken.None));
        Assert.Equal("global", visible.ScopeId);

        global.Members.Add(CreateMember("other-tenant@example.com", "tenant-a"));
        await Assert.ThrowsAsync<ScopeWriteGuardException>(() =>
            global.SaveChangesAsync(CancellationToken.None));
    }

    private static AuthDbContext CreateDbContext()
    {
        DbContextOptions<AuthDbContext> options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-repository-{Guid.NewGuid():N}")
            .Options;

        return new AuthDbContext(options, new TestTenantContext());
    }

    private static Member CreateMember(string username, string scopeId = "tenant-a") =>
        Member.Create(
            new MemberId(Guid.NewGuid()),
            scopeId,
            username,
            MemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            Now).Value;

    private sealed class TestTenantContext(string? scopeId = "tenant-a", bool enabled = true) : IAuthScopeContext
    {
        public bool IsEnabled => enabled;
        public string? ScopeId => scopeId;
        public bool TryRestoreScope(string? scopeId) =>
            !enabled ||
            string.Equals(this.ScopeId, scopeId, StringComparison.Ordinal);
    }
}
