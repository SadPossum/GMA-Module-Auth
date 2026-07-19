namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Messaging.Infrastructure;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options, IAuthScopeContext scopeContext)
    : ScopeAwareDbContext<AuthDbContext>(options, scopeContext)
{
    public DbSet<Member> Members => this.Set<Member>();
    public DbSet<MemberUsername> MemberUsernames => this.Set<MemberUsername>();
    public DbSet<MemberSession> MemberSessions => this.Set<MemberSession>();
    public DbSet<MemberExternalIdentity> MemberExternalIdentities => this.Set<MemberExternalIdentity>();
    public DbSet<PasswordRecoveryChallenge> PasswordRecoveryChallenges => this.Set<PasswordRecoveryChallenge>();
    public DbSet<MemberTotpAuthenticator> MemberTotpAuthenticators => this.Set<MemberTotpAuthenticator>();
    public DbSet<MemberTotpRecoveryCode> MemberTotpRecoveryCodes => this.Set<MemberTotpRecoveryCode>();
    public DbSet<MemberAuthenticationChallenge> MemberAuthenticationChallenges =>
        this.Set<MemberAuthenticationChallenge>();
    public DbSet<MemberMultiFactorFailureAttempt> MemberMultiFactorFailureAttempts =>
        this.Set<MemberMultiFactorFailureAttempt>();
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
