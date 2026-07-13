namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Ports;
using Microsoft.EntityFrameworkCore;

internal sealed class ExternalAuthenticationExchangeStore(AuthDbContext dbContext)
    : IExternalAuthenticationExchangeStore
{
    public async Task AddAsync(ExternalAuthenticationExchange exchange, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(exchange);
        await dbContext.ExternalAuthenticationExchanges.AddAsync(ToRecord(exchange), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ExternalAuthenticationExchange?> ConsumeAsync(
        string codeHash,
        DateTimeOffset consumedAtUtc,
        CancellationToken cancellationToken)
    {
        ExternalAuthenticationExchangeRecord? exchange = await dbContext.ExternalAuthenticationExchanges
            .SingleOrDefaultAsync(
                item => item.CodeHash == codeHash &&
                        item.ConsumedAtUtc == null &&
                        item.ExpiresAtUtc > consumedAtUtc,
                cancellationToken)
            .ConfigureAwait(false);
        if (exchange is null)
        {
            return null;
        }

        exchange.ConsumedAtUtc = consumedAtUtc;
        return ToExchange(exchange);
    }

    public Task<int> DeleteExpiredAsync(
        DateTimeOffset cutoffUtc,
        int batchSize,
        CancellationToken cancellationToken) =>
        dbContext.ExternalAuthenticationExchanges
            .IgnoreQueryFilters()
            .Where(exchange => exchange.ExpiresAtUtc <= cutoffUtc)
            .OrderBy(exchange => exchange.ExpiresAtUtc)
            .Take(batchSize)
            .ExecuteDeleteAsync(cancellationToken);

    private static ExternalAuthenticationExchangeRecord ToRecord(ExternalAuthenticationExchange exchange) =>
        new()
        {
            Id = exchange.Id,
            ScopeId = exchange.ScopeId,
            CodeHash = exchange.CodeHash,
            Intent = (int)exchange.Intent,
            ProviderCode = exchange.ProviderCode,
            Issuer = exchange.Issuer,
            Subject = exchange.Subject,
            Email = exchange.Email,
            EmailVerified = exchange.EmailVerified,
            TargetMemberId = exchange.TargetMemberId,
            TargetSessionId = exchange.TargetSessionId,
            ReturnUrl = exchange.ReturnUrl,
            CreatedAtUtc = exchange.CreatedAtUtc,
            ExpiresAtUtc = exchange.ExpiresAtUtc,
            ConsumedAtUtc = exchange.ConsumedAtUtc,
        };

    private static ExternalAuthenticationExchange ToExchange(ExternalAuthenticationExchangeRecord exchange) =>
        new(
            exchange.Id,
            exchange.ScopeId,
            exchange.CodeHash,
            (ExternalAuthenticationIntent)exchange.Intent,
            exchange.ProviderCode,
            exchange.Issuer,
            exchange.Subject,
            exchange.Email,
            exchange.EmailVerified,
            exchange.TargetMemberId,
            exchange.TargetSessionId,
            exchange.ReturnUrl,
            exchange.CreatedAtUtc,
            exchange.ExpiresAtUtc,
            exchange.ConsumedAtUtc);
}
