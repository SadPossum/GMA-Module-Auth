namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Messaging.Infrastructure;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Persistence.Remembered;
using Gma.Modules.Auth.Persistence.Admission;
using Microsoft.EntityFrameworkCore;
using System.Data;
using Microsoft.EntityFrameworkCore.Storage;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options, IAuthScopeContext scopeContext)
    : ScopeAwareDbContext<AuthDbContext>(options, scopeContext)
{
    public DbSet<Member> Members => this.Set<Member>();
    internal DbSet<RememberedBrowserDevice> RememberedBrowserDevices => this.Set<RememberedBrowserDevice>();
    internal DbSet<RememberedAccountProof> RememberedAccountProofs => this.Set<RememberedAccountProof>();
    internal DbSet<RememberedBrowserOperationReceipt> RememberedBrowserOperations => this.Set<RememberedBrowserOperationReceipt>();
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
    internal DbSet<AuthenticationAttemptRecord> AuthenticationFailureAttempts =>
        this.Set<AuthenticationAttemptRecord>();
    internal DbSet<ExternalAuthenticationExchangeRecord> ExternalAuthenticationExchanges =>
        this.Set<ExternalAuthenticationExchangeRecord>();
    public DbSet<OutboxMessage> OutboxMessages => this.Set<OutboxMessage>();
    public DbSet<InboxMessage> InboxMessages => this.Set<InboxMessage>();

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        if (this.Database.IsNpgsql() && (AuthAdmissionWriteGuard.ChangedKeys(this).Length != 0 ||
            AuthAdmissionWriteGuard.ChangedDeviceIds(this).Length != 0))
        {
            throw new InvalidOperationException("PostgreSQL Auth invalidations require asynchronous transaction fencing.");
        }
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess,
        CancellationToken cancellationToken = default)
    {
        AuthAdmissionLockKey[] keys = this.Database.IsNpgsql() ? AuthAdmissionWriteGuard.ChangedKeys(this) : [];
        Guid[] devices = this.Database.IsNpgsql() ? AuthAdmissionWriteGuard.ChangedDeviceIds(this) : [];
        if (keys.Length == 0 && devices.Length == 0)
        {
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken).ConfigureAwait(false);
        }

        if (System.Transactions.Transaction.Current is not null)
        {
            throw new InvalidOperationException("Ambient Auth invalidation transactions are unsupported.");
        }
        IDbContextTransaction? owned = this.Database.CurrentTransaction is null
            ? await this.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false)
            : null;
        try
        {
            string ownerIdentity = await AuthAdmissionLockKey.AcquireDeviceRowsAsync(this, devices, cancellationToken)
                .ConfigureAwait(false);
            keys = AuthAdmissionLockKey.Ordered(keys.Concat(await AuthAdmissionWriteGuard
                .ReadPersistedDeviceKeysAsync(this, devices, cancellationToken).ConfigureAwait(false)));
            await AuthAdmissionWriteGuard.AcquireAsync(this, keys, cancellationToken, ownerIdentity).ConfigureAwait(false);
            int result = await base.SaveChangesAsync(owned is null && acceptAllChangesOnSuccess, cancellationToken).ConfigureAwait(false);
            if (owned is not null)
            {
                await owned.CommitAsync(cancellationToken).ConfigureAwait(false);
                if (acceptAllChangesOnSuccess)
                {
                    this.ChangeTracker.AcceptAllChanges();
                }
            }
            return result;
        }
        finally
        {
            if (owned is not null)
            {
                await owned.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(AuthMigrations.Schema);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);
        this.ApplyScopeConventions(modelBuilder);
    }
}
