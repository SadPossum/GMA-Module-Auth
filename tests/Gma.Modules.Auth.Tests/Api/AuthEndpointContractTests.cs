namespace Gma.Modules.Auth.Tests.Api;

using Gma.Framework.Api.Modules;
using Gma.Framework.Infrastructure;
using Gma.Modules.Auth.Api;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Providers.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthEndpointContractTests
{
    [Fact]
    public async Task Endpoint_graph_materializes_with_password_and_identity_proof_bodies()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(
        [
            new("Auth:Jwt:SigningKey", "test-jwt-signing-key-000000000000000000000000"),
            new("Auth:RefreshTokens:Pepper", "test-refresh-token-pepper-000000000000000000000000"),
            new("Persistence:Provider", "SqlServer"),
            new("ConnectionStrings:SqlServer", "Server=(localdb)\\mssqllocaldb;Database=GmaAuthEndpointTests;Trusted_Connection=True;")
        ]);
        builder.AddGmaInfrastructure();
        builder.AddAuthModule(AuthProfile.Global("global"));
        builder.AddAuthOpenIdConnectProviders();

        await using WebApplication app = builder.Build();
        app.MapModules();

        string[] routes = [.. ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(dataSource => dataSource.Endpoints)
            .OfType<RouteEndpoint>()
            .Select(endpoint => endpoint.RoutePattern.RawText)
            .OfType<string>()];

        Assert.Contains("/api/auth/password/remove", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/password-recovery", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/password-recovery/confirm", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/sessions", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/sessions/{sessionId:guid}/sign-out", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/step-up/password", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/step-up/password", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/self-registration", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/external-identities/{externalIdentityId:guid}/unlink", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/external/providers", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/external/{provider}/sign-in/challenge", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/external/{provider}/link/challenge", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/external/challenge/{nonce}", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/mfa", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/mfa/totp/enrollment", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/mfa/totp/activate", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/mfa/challenges/complete", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/mfa/recovery-codes/regenerate", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/mfa/totp/disable", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/mfa/totp/activate", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/mfa/challenges/complete", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/mfa/recovery-codes/regenerate", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/mfa/totp/disable", routes, StringComparer.Ordinal);

        RouteEndpoint[] recoveryEndpoints = [.. ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(dataSource => dataSource.Endpoints)
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText is
                "/api/auth/password-recovery" or "/api/auth/password-recovery/confirm")];
        Assert.Equal(2, recoveryEndpoints.Length);
        Assert.All(recoveryEndpoints, endpoint =>
            Assert.Empty(endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()));
    }
}
