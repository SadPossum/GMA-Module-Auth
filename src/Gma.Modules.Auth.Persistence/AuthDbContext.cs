namespace Gma.Modules.Auth.Persistence;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Scoping;
using Gma.Framework.Messaging.Infrastructure;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options, IScopeContext scopeContext)
    : ScopeAwareDbContext<AuthDbContext>(options, scopeContext)
{
    public DbSet<Member> Members => this.Set<Member>();
    public DbSet<MemberUsername> MemberUsernames => this.Set<MemberUsername>();
    public DbSet<MemberSession> MemberSessions => this.Set<MemberSession>();
    public DbSet<MemberExternalIdentity> MemberExternalIdentities => this.Set<MemberExternalIdentity>();
    internal DbSet<ExternalAuthenticationExchangeRecord> ExternalAuthenticationExchanges =>
        this.Set<ExternalAuthenticationExchangeRecord>();
    public DbSet<OutboxMessage> OutboxMessages => this.Set<OutboxMessage>();
    public DbSet<InboxMessage> InboxMessages => this.Set<InboxMessage>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(AuthMigrations.Schema);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);
        this.ApplyScopeConventions(modelBuilder);
    }
}
