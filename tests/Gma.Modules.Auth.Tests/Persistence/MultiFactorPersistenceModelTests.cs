namespace Gma.Modules.Auth.Tests.Persistence;

using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Xunit;

[Trait("Category", "Unit")]
public sealed class MultiFactorPersistenceModelTests
{
    [Fact]
    public void Persistence_model_enforces_authenticator_and_challenge_concurrency_boundaries()
    {
        using AuthDbContext dbContext = new(
            new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase($"auth-mfa-model-{Guid.NewGuid():N}")
                .Options,
            new TestScopeContext());

        IEntityType authenticator = dbContext.Model.FindEntityType(typeof(MemberTotpAuthenticator))!;
        IEntityType challenge = dbContext.Model.FindEntityType(typeof(MemberAuthenticationChallenge))!;
        IEntityType failureAttempt = dbContext.Model.FindEntityType(typeof(MemberMultiFactorFailureAttempt))!;

        Assert.True(authenticator.FindProperty(nameof(MemberTotpAuthenticator.ConcurrencyStamp))!.IsConcurrencyToken);
        Assert.True(challenge.FindProperty(nameof(MemberAuthenticationChallenge.ConcurrencyStamp))!.IsConcurrencyToken);
        Assert.Contains(authenticator.GetIndexes(), index =>
            index.IsUnique && HasProperties(
                index,
                nameof(MemberTotpAuthenticator.ScopeId),
                nameof(MemberTotpAuthenticator.MemberId)));
        Assert.Contains(challenge.GetIndexes(), index =>
            index.IsUnique && HasProperties(
                index,
                nameof(MemberAuthenticationChallenge.ScopeId),
                nameof(MemberAuthenticationChallenge.TokenHash)));
        Assert.Contains(failureAttempt.GetIndexes(), index => HasProperties(
            index,
            nameof(MemberMultiFactorFailureAttempt.ScopeId),
            nameof(MemberMultiFactorFailureAttempt.MemberId),
            nameof(MemberMultiFactorFailureAttempt.Purpose),
            nameof(MemberMultiFactorFailureAttempt.FailedAtUtc)));
    }

    private static bool HasProperties(IIndex index, params string[] names) =>
        index.Properties.Select(property => property.Name).SequenceEqual(names);

    private sealed class TestScopeContext : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string? ScopeId => "tenant-a";
        public bool TryRestoreScope(string? scopeId) =>
            string.Equals(this.ScopeId, scopeId, StringComparison.Ordinal);
    }
}
