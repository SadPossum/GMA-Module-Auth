namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Xunit;
using DomainMemberUsernameType = Gma.Modules.Auth.Domain.Enums.MemberUsernameType;

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

    [Fact]
    public async Task Admission_reader_returns_only_active_members_from_the_exact_scope()
    {
        string databaseName = $"auth-admission-reader-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid activeMemberId = Guid.NewGuid();
        Guid unverifiedMemberId = Guid.NewGuid();
        Guid disabledMemberId = Guid.NewGuid();
        DateTimeOffset nowUtc = DateTimeOffset.UtcNow;

        await using (AuthDbContext tenantA = CreateDbContext(databaseName, databaseRoot, "tenant-a"))
        {
            Member activeMember = CreateExternalMember(activeMemberId, "tenant-a", "active@example.com", nowUtc);
            Member unverifiedMember = Member.Create(
                new MemberId(unverifiedMemberId),
                "tenant-a",
                "unverified@example.com",
                DomainMemberUsernameType.Email,
                "password-hash",
                new MemberUsernameId(Guid.NewGuid()),
                Guid.NewGuid(),
                nowUtc).Value;
            Member disabledMember = CreateExternalMember(disabledMemberId, "tenant-a", "disabled@example.com", nowUtc);
            Assert.True(disabledMember.Disable("disabled for test", Guid.NewGuid(), nowUtc).IsSuccess);

            tenantA.Members.AddRange(activeMember, unverifiedMember, disabledMember);
            await tenantA.SaveChangesAsync();
        }

        await using AuthDbContext workerContext = CreateDbContext(databaseName, databaseRoot, "worker-default");
        var reader = new AuthMemberAdmissionReader(workerContext);

        AuthMemberAdmission? active = await reader.FindActiveAsync("tenant-a", activeMemberId);
        AuthMemberAdmission? unverified = await reader.FindActiveAsync("tenant-a", unverifiedMemberId);
        AuthMemberAdmission? disabled = await reader.FindActiveAsync("tenant-a", disabledMemberId);
        AuthMemberAdmission? missing = await reader.FindActiveAsync("tenant-a", Guid.NewGuid());
        AuthMemberAdmission? otherScope = await reader.FindActiveAsync("tenant-b", activeMemberId);

        Assert.Equal("active@example.com", Assert.IsType<AuthMemberAdmission>(active).PreferredVerifiedEmail);
        Assert.Null(Assert.IsType<AuthMemberAdmission>(unverified).PreferredVerifiedEmail);
        Assert.Null(disabled);
        Assert.Null(missing);
        Assert.Null(otherScope);
    }

    [Fact]
    public async Task Contact_reader_keeps_disabled_member_contact_for_auth_owned_security_delivery()
    {
        string databaseName = $"auth-disabled-contact-reader-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid memberId = Guid.NewGuid();
        DateTimeOffset nowUtc = DateTimeOffset.UtcNow;

        await using (AuthDbContext tenantA = CreateDbContext(databaseName, databaseRoot, "tenant-a"))
        {
            Member member = CreateExternalMember(memberId, "tenant-a", "security@example.com", nowUtc);
            Assert.True(member.Disable("disabled for test", Guid.NewGuid(), nowUtc).IsSuccess);
            tenantA.Members.Add(member);
            await tenantA.SaveChangesAsync();
        }

        await using AuthDbContext workerContext = CreateDbContext(databaseName, databaseRoot, "worker-default");
        var reader = new AuthMemberContactReader(workerContext);

        string? email = await reader.GetPreferredVerifiedEmailAsync("tenant-a", memberId);

        Assert.Equal("security@example.com", email);
    }

    private static Member CreateExternalMember(
        Guid memberId,
        string scopeId,
        string email,
        DateTimeOffset nowUtc) =>
        Member.CreateExternal(
            new MemberId(memberId),
            scopeId,
            email,
            new MemberUsernameId(Guid.NewGuid()),
            new MemberExternalIdentityId(Guid.NewGuid()),
            "google",
            "https://accounts.google.com",
            $"subject-{memberId:N}",
            Guid.NewGuid(),
            nowUtc).Value;

    private static AuthDbContext CreateDbContext(
        string databaseName,
        InMemoryDatabaseRoot databaseRoot,
        string scopeId) =>
        new(
            new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName, databaseRoot)
                .Options,
            new TestScopeContext(scopeId));

    private sealed class TestScopeContext(string scopeId) : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => scopeId;
        public bool TryRestoreScope(string? candidate) =>
            string.Equals(scopeId, candidate, StringComparison.Ordinal);
    }
}
