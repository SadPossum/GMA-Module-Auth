namespace Gma.Modules.Auth.Tests.Api;

using Gma.Framework.Api.Modules;
using Gma.Framework.Infrastructure;
using Gma.Modules.Auth.Api;
using Gma.Modules.Auth.Contracts;
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

        await using WebApplication app = builder.Build();
        app.MapModules();

        string[] routes = [.. ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(dataSource => dataSource.Endpoints)
            .OfType<RouteEndpoint>()
            .Select(endpoint => endpoint.RoutePattern.RawText)
            .OfType<string>()];

        Assert.Contains("/api/auth/password/remove", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/external-identities/{externalIdentityId:guid}/unlink", routes, StringComparer.Ordinal);
    }
}
