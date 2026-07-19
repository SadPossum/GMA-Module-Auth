namespace Gma.Modules.Auth.Tests.Api;

using System.Net;
using System.Text;
using Gma.Framework.Api.Modules;
using Gma.Framework.Api.Security;
using Gma.Framework.Infrastructure;
using Gma.Modules.Auth.Api;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Providers.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
        builder.Services.AddApiSecurityDefaults();
        builder.AddGmaInfrastructure();
        builder.AddAuthModule(AuthProfile.Global("global"));
        builder.AddAuthOpenIdConnectProviders();

        await using WebApplication app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
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

        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        IServer server = app.Services.GetRequiredService<IServer>();
        string address = Assert.Single(server.Features.Get<IServerAddressesFeature>()!.Addresses);
        using var client = new HttpClient { BaseAddress = new Uri(address) };

        using HttpResponseMessage coreResponse = await client.GetAsync("/api/auth/self-registration");
        using HttpResponseMessage contributedResponse = await client.GetAsync("/api/auth/external/providers");
        using HttpResponseMessage unauthorizedResponse = await client.GetAsync("/api/auth/sessions");
        using var malformedContent = new StringContent("{", Encoding.UTF8, "application/json");
        using HttpResponseMessage malformedResponse = await client.PostAsync("/api/auth/login", malformedContent);
        using HttpResponseMessage missingResponse = await client.GetAsync("/api/auth/not-a-route");

        Assert.Equal(HttpStatusCode.Unauthorized, unauthorizedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, malformedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missingResponse.StatusCode);
        AssertNoStore(coreResponse);
        AssertNoStore(contributedResponse);
        AssertNoStore(unauthorizedResponse);
        AssertNoStore(malformedResponse);
        AssertNoStore(missingResponse);
    }

    private static void AssertNoStore(HttpResponseMessage response)
    {
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.Select(value => value.Name));
    }
}
