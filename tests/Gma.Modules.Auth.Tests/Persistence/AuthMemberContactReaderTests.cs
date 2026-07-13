namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Scoping;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthMemberContactReaderTests
{
    [Fact]
    public async Task Explicit_scope_lookup_works_from_a_worker_scope_without_crossing_tenants()
    {
        string databaseName = $"auth-contact-reader-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid memberId = Guid.NewGuid();
        await using (AuthDbContext tenantA = CreateDbContext(databaseName, databaseRoot, "tenant-a"))
        {
            Member member = Member.CreateExternal(
                new MemberId(memberId),
                "tenant-a",
                "member@example.com",
                new MemberUsernameId(Guid.NewGuid()),
                new MemberExternalIdentityId(Guid.NewGuid()),
                "google",
                "https://accounts.google.com",
                "google-subject",
                Guid.NewGuid(),
                DateTimeOffset.UtcNow).Value;
            tenantA.Members.Add(member);
            await tenantA.SaveChangesAsync();
        }

        await using AuthDbContext workerContext = CreateDbContext(databaseName, databaseRoot, "worker-default");
        var reader = new AuthMemberContactReader(workerContext);

        string? tenantAEmail = await reader.GetPreferredVerifiedEmailAsync("tenant-a", memberId);
        string? otherTenantEmail = await reader.GetPreferredVerifiedEmailAsync("tenant-b", memberId);

        Assert.Equal("member@example.com", tenantAEmail);
        Assert.Null(otherTenantEmail);
    }

    private static AuthDbContext CreateDbContext(
        string databaseName,
        InMemoryDatabaseRoot databaseRoot,
        string scopeId) =>
        new(
            new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName, databaseRoot)
                .Options,
            new TestScopeContext(scopeId));

    private sealed class TestScopeContext(string scopeId) : IScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => scopeId;
    }
}
