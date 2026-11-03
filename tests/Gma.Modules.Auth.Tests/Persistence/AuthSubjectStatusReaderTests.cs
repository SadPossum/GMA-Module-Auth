namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Naming;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Scoping;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using DomainMemberStatus = Gma.Modules.Auth.Domain.Enums.MemberStatus;
using DomainMemberUsernameType = Gma.Modules.Auth.Domain.Enums.MemberUsernameType;

[Trait("Category", "Unit")]
public sealed class AuthSubjectStatusReaderTests
{
    [Fact]
    public async Task Current_scope_lookup_returns_canonical_status_without_tracking()
    {
        string databaseName = $"auth-subject-status-reader-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid activeId = Guid.Parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        Guid disabledId = Guid.Parse("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff");
        Guid unknownId = Guid.Parse("cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa");
        var authScope = new MutableAuthScopeContext("Tenant-Case");
        await using (AuthDbContext seed = CreateDbContext(databaseName, databaseRoot, authScope))
        {
            Member active = CreateMember(activeId, "Tenant-Case", "active@example.com");
            Member disabled = CreateMember(disabledId, "Tenant-Case", "disabled@example.com");
            Assert.True(disabled.Disable("support action", Guid.NewGuid(), DateTimeOffset.UtcNow).IsSuccess);
            Member unknown = CreateMember(unknownId, "Tenant-Case", "unknown@example.com");
            seed.Members.AddRange(active, disabled, unknown);
            seed.Entry(unknown).Property(member => member.Status).CurrentValue = (DomainMemberStatus)999;
            await seed.SaveChangesAsync();
        }

        await using AuthDbContext worker = CreateDbContext(databaseName, databaseRoot, authScope);
        var reader = new AuthSubjectStatusReader(worker, authScope);

        AuthSubjectStatusSnapshot? activeStatus = await reader.FindAsync(
            $" {{{activeId.ToString("D").ToUpperInvariant()}}} ");
        AuthSubjectStatusSnapshot? disabledStatus = await reader.FindAsync(disabledId.ToString("D"));
        AuthSubjectStatusSnapshot? unknownStatus = await reader.FindAsync(unknownId.ToString("D"));

        Assert.Equal(
            new AuthSubjectStatusSnapshot("Tenant-Case", activeId.ToString("D"), MemberStatus.Active),
            activeStatus);
        Assert.Equal(MemberStatus.Disabled, Assert.IsType<AuthSubjectStatusSnapshot>(disabledStatus).Status);
        Assert.Equal(MemberStatus.Unknown, Assert.IsType<AuthSubjectStatusSnapshot>(unknownStatus).Status);
        Assert.Null(await reader.FindAsync(Guid.NewGuid().ToString("D")));
        Assert.Empty(worker.ChangeTracker.Entries());
    }

    [Fact]
    public async Task Global_profile_reader_cannot_read_a_member_outside_its_fixed_scope()
    {
        string databaseName = $"auth-subject-status-global-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid identityMemberId = Guid.NewGuid();
        Guid otherMemberId = Guid.NewGuid();
        await SeedMemberAsync(databaseName, databaseRoot, "identity", identityMemberId, "identity@example.com");
        await SeedMemberAsync(databaseName, databaseRoot, "other-scope", otherMemberId, "other@example.com");

        var services = new ServiceCollection();
        services.AddAuthScopeContext(AuthProfile.Global("identity"));
        await using ServiceProvider provider = services.BuildServiceProvider(validateScopes: true);
        await using AsyncServiceScope serviceScope = provider.CreateAsyncScope();
        IAuthScopeContext authScope = serviceScope.ServiceProvider.GetRequiredService<IAuthScopeContext>();
        await using AuthDbContext dbContext = CreateDbContext(databaseName, databaseRoot, authScope);
        var reader = new AuthSubjectStatusReader(dbContext, authScope);

        AuthSubjectStatusSnapshot identity = Assert.IsType<AuthSubjectStatusSnapshot>(
            await reader.FindAsync(identityMemberId.ToString("D")));

        Assert.Equal("identity", identity.ScopeId);
        Assert.Null(await reader.FindAsync(otherMemberId.ToString("D")));
        Assert.True(authScope.TryRestoreScope("identity"));
        Assert.False(authScope.TryRestoreScope("other-scope"));
    }

    [Fact]
    public async Task Scope_aware_reader_follows_only_the_restored_ambient_scope()
    {
        string databaseName = $"auth-subject-status-ambient-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid tenantAMemberId = Guid.NewGuid();
        Guid tenantBMemberId = Guid.NewGuid();
        await SeedMemberAsync(databaseName, databaseRoot, "tenant-a", tenantAMemberId, "tenant-a@example.com");
        await SeedMemberAsync(databaseName, databaseRoot, "tenant-b", tenantBMemberId, "tenant-b@example.com");

        HostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Services.AddScoped<IScopeContextAccessor>(_ => new MutableScopeContextAccessor());
        builder.Services.AddAuthScopeContext(AuthProfile.ScopeAware());
        builder.Services.AddDbContext<AuthDbContext>(options =>
            options.UseInMemoryDatabase(databaseName, databaseRoot));
        builder.AddAuthSubjectStatusReader();
        await using ServiceProvider provider = builder.Services.BuildServiceProvider(validateScopes: true);

        await using (AsyncServiceScope tenantAScope = provider.CreateAsyncScope())
        {
            IAuthScopeContext authScope = tenantAScope.ServiceProvider.GetRequiredService<IAuthScopeContext>();
            Assert.True(authScope.TryRestoreScope("tenant-a"));
            IAuthSubjectStatusReader reader = tenantAScope.ServiceProvider
                .GetRequiredService<IAuthSubjectStatusReader>();

            Assert.Equal(
                "tenant-a",
                Assert.IsType<AuthSubjectStatusSnapshot>(
                    await reader.FindAsync(tenantAMemberId.ToString("D"))).ScopeId);
            Assert.Null(await reader.FindAsync(tenantBMemberId.ToString("D")));
        }

        await using (AsyncServiceScope tenantBScope = provider.CreateAsyncScope())
        {
            IAuthScopeContext authScope = tenantBScope.ServiceProvider.GetRequiredService<IAuthScopeContext>();
            Assert.True(authScope.TryRestoreScope("tenant-b"));
            IAuthSubjectStatusReader reader = tenantBScope.ServiceProvider
                .GetRequiredService<IAuthSubjectStatusReader>();

            Assert.Equal(
                "tenant-b",
                Assert.IsType<AuthSubjectStatusSnapshot>(
                    await reader.FindAsync(tenantBMemberId.ToString("D"))).ScopeId);
            Assert.Null(await reader.FindAsync(tenantAMemberId.ToString("D")));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-subject")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public async Task Invalid_subject_is_not_a_member_and_does_not_query_persistence(string? subjectId)
    {
        var authScope = new MutableAuthScopeContext("identity");
        AuthDbContext context = CreateDbContext(
            $"auth-subject-status-invalid-{Guid.NewGuid():N}",
            new InMemoryDatabaseRoot(),
            authScope);
        var reader = new AuthSubjectStatusReader(context, authScope);
        await context.DisposeAsync();

        AuthSubjectStatusSnapshot? status = await reader.FindAsync(subjectId!);

        Assert.Null(status);
    }

    [Theory]
    [MemberData(nameof(InvalidScopeContexts))]
    public async Task Missing_disabled_or_invalid_scope_context_fails_closed(
        bool isEnabled,
        string? scopeId)
    {
        var authScope = new MutableAuthScopeContext(scopeId, isEnabled);
        await using AuthDbContext context = CreateDbContext(
            $"auth-subject-status-scope-{Guid.NewGuid():N}",
            new InMemoryDatabaseRoot(),
            authScope);
        var reader = new AuthSubjectStatusReader(context, authScope);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reader.FindAsync(Guid.NewGuid().ToString("D")).AsTask());

        Assert.Contains("enabled and valid Auth scope context", exception.Message, StringComparison.Ordinal);
    }

    public static TheoryData<bool, string?> InvalidScopeContexts => new()
    {
        { false, "identity" },
        { true, null },
        { true, " " },
        { true, "invalid scope" },
        { true, new string('a', ScopeIds.MaxLength + 1) },
    };

    [Fact]
    public async Task Reader_and_db_context_must_share_the_same_scope()
    {
        var dbScope = new MutableAuthScopeContext("tenant-a");
        var readerScope = new MutableAuthScopeContext("tenant-b");
        await using AuthDbContext context = CreateDbContext(
            $"auth-subject-status-mismatch-{Guid.NewGuid():N}",
            new InMemoryDatabaseRoot(),
            dbScope);
        var reader = new AuthSubjectStatusReader(context, readerScope);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reader.FindAsync(Guid.NewGuid().ToString("D")).AsTask());
    }

    [Fact]
    public async Task Cancellation_is_forwarded_to_the_provider_query()
    {
        string databaseName = $"auth-subject-status-cancellation-{Guid.NewGuid():N}";
        InMemoryDatabaseRoot databaseRoot = new();
        Guid memberId = Guid.NewGuid();
        await SeedMemberAsync(databaseName, databaseRoot, "identity", memberId, "cancelled@example.com");

        var authScope = new MutableAuthScopeContext("identity");
        await using AuthDbContext worker = CreateDbContext(databaseName, databaseRoot, authScope);
        var reader = new AuthSubjectStatusReader(worker, authScope);
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            reader.FindAsync(memberId.ToString("D"), cancellation.Token).AsTask());
    }

    [Fact]
    public void Registration_is_explicit_idempotent_and_preserves_a_replacement()
    {
        HostApplicationBuilder defaultBuilder = Host.CreateApplicationBuilder();

        Assert.DoesNotContain(
            defaultBuilder.Services,
            descriptor => descriptor.ServiceType == typeof(IAuthSubjectStatusReader));

        defaultBuilder.AddAuthSubjectStatusReader();
        defaultBuilder.AddAuthSubjectStatusReader();

        ServiceDescriptor registration = Assert.Single(
            defaultBuilder.Services,
            descriptor => descriptor.ServiceType == typeof(IAuthSubjectStatusReader));
        Assert.Equal(typeof(AuthSubjectStatusReader), registration.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, registration.Lifetime);

        HostApplicationBuilder replacementBuilder = Host.CreateApplicationBuilder();
        var replacement = new StubSubjectStatusReader();
        replacementBuilder.Services.AddSingleton<IAuthSubjectStatusReader>(replacement);

        replacementBuilder.AddAuthSubjectStatusReader();

        ServiceDescriptor preserved = Assert.Single(
            replacementBuilder.Services,
            descriptor => descriptor.ServiceType == typeof(IAuthSubjectStatusReader));
        Assert.Same(replacement, preserved.ImplementationInstance);
    }

    private static async Task SeedMemberAsync(
        string databaseName,
        InMemoryDatabaseRoot databaseRoot,
        string scopeId,
        Guid memberId,
        string username)
    {
        var scope = new MutableAuthScopeContext(scopeId);
        await using AuthDbContext dbContext = CreateDbContext(databaseName, databaseRoot, scope);
        dbContext.Members.Add(CreateMember(memberId, scopeId, username));
        await dbContext.SaveChangesAsync();
    }

    private static Member CreateMember(Guid memberId, string scopeId, string username) =>
        Member.Create(
            new MemberId(memberId),
            scopeId,
            username,
            DomainMemberUsernameType.Email,
            "password-hash",
            new MemberUsernameId(Guid.NewGuid()),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow).Value;

    private static AuthDbContext CreateDbContext(
        string databaseName,
        InMemoryDatabaseRoot databaseRoot,
        IAuthScopeContext scopeContext) =>
        new(
            new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName, databaseRoot)
                .Options,
            scopeContext);

    private sealed class MutableAuthScopeContext(string? scopeId, bool isEnabled = true) : IAuthScopeContext
    {
        public bool IsEnabled { get; } = isEnabled;
        public string? ScopeId { get; private set; } = scopeId;

        public bool TryRestoreScope(string? candidate)
        {
            this.ScopeId = candidate;
            return true;
        }
    }

    private sealed class MutableScopeContextAccessor : IScopeContextAccessor
    {
        public bool IsEnabled => true;
        public string? ScopeId { get; private set; }
        public void SetScope(string scopeId) => this.ScopeId = scopeId;
        public void ClearScope() => this.ScopeId = null;
    }

    private sealed class StubSubjectStatusReader : IAuthSubjectStatusReader
    {
        public ValueTask<AuthSubjectStatusSnapshot?> FindAsync(
            string subjectId,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<AuthSubjectStatusSnapshot?>(null);
    }
}
