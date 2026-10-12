namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Application.Events;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Cqrs.UnitOfWork;
using Gma.Modules.Auth.Persistence.Remembered;

internal sealed class AuthUnitOfWork(
    AuthDbContext dbContext,
    IDomainEventDispatcher domainEventDispatcher,
    RememberedBrowserService? remembered = null)
    : EfDomainEventUnitOfWork<AuthDbContext>(AuthMigrations.Schema, dbContext, domainEventDispatcher),
        ITransactionalUnitOfWork
{
    public new async Task BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        await base.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        if (remembered is not null)
        {
            await remembered.BeginAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public new async Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        if (remembered is not null)
        {
            await remembered.BindIssuedSessionsAsync(cancellationToken).ConfigureAwait(false);
        }

        await base.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
