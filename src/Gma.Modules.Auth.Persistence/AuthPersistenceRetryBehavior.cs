namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Cqrs;
using Gma.Framework.Observability.Infrastructure;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Framework.Results;
using Gma.Modules.Auth.Contracts;
using Microsoft.EntityFrameworkCore;

internal sealed class AuthPersistenceRetryBehavior<TCommand, TResponse>
    : ICommandPipelineBehavior<TCommand, TResponse>
    where TCommand : ICommand<TResponse>
{
    private readonly AuthDbContext dbContext;
    private readonly Func<DbUpdateException, bool> isRetryableUniqueViolation;

    public AuthPersistenceRetryBehavior(AuthDbContext dbContext)
        : this(dbContext, EfDatabaseExceptionClassifier.IsUniqueConstraintViolation)
    {
    }

    internal AuthPersistenceRetryBehavior(
        AuthDbContext dbContext,
        Func<DbUpdateException, bool> isRetryableUniqueViolation)
    {
        this.dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        this.isRetryableUniqueViolation = isRetryableUniqueViolation ??
            throw new ArgumentNullException(nameof(isRetryableUniqueViolation));
    }

    public async Task<Result<TResponse>> HandleAsync(
        TCommand command,
        CommandNext<TResponse> next,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(next);

        if (!string.Equals(
                ModuleNameResolver.FromType(typeof(TCommand)),
                AuthModuleMetadata.Name,
                StringComparison.Ordinal))
        {
            return await next().ConfigureAwait(false);
        }

        try
        {
            return await next().ConfigureAwait(false);
        }
        catch (OptimisticConcurrencyException)
        {
            this.dbContext.ChangeTracker.Clear();
            return await next().ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException)
        {
            this.dbContext.ChangeTracker.Clear();
            return await next().ConfigureAwait(false);
        }
        catch (DbUpdateException exception)
            when (this.isRetryableUniqueViolation(exception))
        {
            this.dbContext.ChangeTracker.Clear();
            return await next().ConfigureAwait(false);
        }
    }
}
