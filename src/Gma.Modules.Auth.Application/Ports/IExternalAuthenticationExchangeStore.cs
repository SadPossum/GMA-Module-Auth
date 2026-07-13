namespace Gma.Modules.Auth.Application.Ports;

using Gma.Modules.Auth.Application.ExternalAuthentication;

public interface IExternalAuthenticationExchangeStore
{
    Task AddAsync(ExternalAuthenticationExchange exchange, CancellationToken cancellationToken);
    Task<ExternalAuthenticationExchange?> ConsumeAsync(
        string codeHash,
        DateTimeOffset consumedAtUtc,
        CancellationToken cancellationToken);
    Task<int> DeleteExpiredAsync(DateTimeOffset cutoffUtc, int batchSize, CancellationToken cancellationToken);
}
