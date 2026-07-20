namespace Gma.Modules.Auth.Tests.Persistence;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Persistence;
using Microsoft.EntityFrameworkCore;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthPersistenceRetryBehaviorTests
{
    [Fact]
    public async Task Retryable_unique_conflict_clears_tracking_and_reexecutes_once()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        AuthPersistenceRetryBehavior<RegisterMemberCommand, AuthTokensResponse> behavior =
            new(dbContext, _ => true);
        RegisterMemberCommand command = new("member@example.com", UsernameType.Email, "password");
        int attempts = 0;

        Task<Result<AuthTokensResponse>> Next()
        {
            attempts++;
            if (attempts == 1)
            {
                dbContext.AuthenticationFailureAttempts.Add(new AuthenticationAttemptRecord
                {
                    Id = Guid.NewGuid(),
                    ScopeId = "global",
                    Purpose = "password-login",
                    TargetHash = "target-hash",
                    FailedAtUtc = DateTimeOffset.UtcNow,
                });
                throw new DbUpdateException("simulated unique conflict");
            }

            Assert.Empty(dbContext.ChangeTracker.Entries());
            return Task.FromResult(Result.Failure<AuthTokensResponse>(AuthDomainErrors.UsernameAlreadyExists));
        }

        Result<AuthTokensResponse> result = await behavior.HandleAsync(
            command,
            Next,
            CancellationToken.None);

        Assert.Equal(2, attempts);
        Assert.Equal(AuthDomainErrors.UsernameAlreadyExists, result.Error);
    }

    [Fact]
    public async Task Translated_concurrency_conflict_is_reexecuted_only_once()
    {
        await using AuthDbContext dbContext = CreateDbContext();
        AuthPersistenceRetryBehavior<RegisterMemberCommand, AuthTokensResponse> behavior =
            new(dbContext, _ => false);
        RegisterMemberCommand command = new("member@example.com", UsernameType.Email, "password");
        int attempts = 0;

        Task<Result<AuthTokensResponse>> Next()
        {
            attempts++;
            if (attempts == 1)
            {
                throw new OptimisticConcurrencyException(
                    AuthModuleMetadata.Name,
                    new DbUpdateConcurrencyException("simulated concurrency conflict"));
            }

            return Task.FromResult(Result.Failure<AuthTokensResponse>(AuthDomainErrors.UsernameAlreadyExists));
        }

        Result<AuthTokensResponse> result = await behavior.HandleAsync(
            command,
            Next,
            CancellationToken.None);

        Assert.Equal(2, attempts);
        Assert.Equal(AuthDomainErrors.UsernameAlreadyExists, result.Error);
    }

    private static AuthDbContext CreateDbContext() => new(
        new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"auth-retry-{Guid.NewGuid():N}")
            .Options,
        new TestScopeContext());

    private sealed class TestScopeContext : IAuthScopeContext
    {
        public bool IsEnabled => false;
        public string? ScopeId => null;
        public bool TryRestoreScope(string? scopeId) => true;
    }
}
