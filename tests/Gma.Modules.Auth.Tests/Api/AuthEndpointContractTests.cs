namespace Gma.Modules.Auth.Tests.Api;

using System.Net;
using System.Security.Claims;
using System.Text;
using Gma.Framework.Api.Modules;
using Gma.Framework.Api.Security;
using Gma.Framework.Administration.Api;
using Gma.Framework.Infrastructure;
using Gma.Modules.Auth.AdminApi;
using Gma.Modules.Auth.Api;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Providers.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Metadata;
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

        RouteEndpoint[] endpoints = [.. ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(dataSource => dataSource.Endpoints)
            .OfType<RouteEndpoint>()];
        string[] routes = [.. endpoints
            .Select(endpoint => endpoint.RoutePattern.RawText)
            .OfType<string>()];

        Assert.Contains("/api/auth/password/remove", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/password-recovery", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/password-recovery/confirm", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/sessions", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/sessions/{sessionId:guid}/sign-out", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/step-up/password", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/step-up/password", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/password", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/browser/password/remove", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/self-registration", routes, StringComparer.Ordinal);
        Assert.Contains("/api/auth/external-identities/{externalIdentityId:guid}/unlink", routes, StringComparer.Ordinal);
        Assert.Contains(
            "/api/auth/browser/external-identities/{externalIdentityId:guid}/unlink",
            routes,
            StringComparer.Ordinal);
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

        RouteEndpoint registerEndpoint = GetEndpoint(endpoints, "/api/auth/register", "POST");
        Assert.Equal(
            typeof(RegisterMemberRequest),
            Assert.IsType<IAcceptsMetadata>(
                registerEndpoint.Metadata.GetMetadata<IAcceptsMetadata>(),
                exactMatch: false).RequestType);
        AssertProduces(registerEndpoint, StatusCodes.Status200OK, typeof(AuthTokensResponse));
        AssertProduces(GetEndpoint(endpoints, "/api/auth/refresh", "POST"), StatusCodes.Status200OK, typeof(AuthTokensResponse));
        AssertProduces(GetEndpoint(endpoints, "/api/auth/sign-out", "POST"), StatusCodes.Status204NoContent);
        AssertProduces(GetEndpoint(endpoints, "/api/auth/email-verification", "POST"), StatusCodes.Status202Accepted);
        AssertProduces(GetEndpoint(endpoints, "/api/auth/email-verification/confirm", "POST"), StatusCodes.Status204NoContent);
        AssertProduces(GetEndpoint(endpoints, "/api/auth/browser/sign-out", "POST"), StatusCodes.Status204NoContent);
        AssertProduces(GetEndpoint(endpoints, "/api/auth/external/{provider}/sign-in", "GET"), StatusCodes.Status302Found);

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

    [Fact]
    public async Task Admin_endpoint_graph_declares_typed_success_contracts()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(
        [
            new("Auth:Jwt:SigningKey", "test-jwt-signing-key-000000000000000000000000"),
            new("Auth:RefreshTokens:Pepper", "test-refresh-token-pepper-000000000000000000000000"),
            new("Persistence:Provider", "SqlServer"),
            new("ConnectionStrings:SqlServer", "Server=(localdb)\\mssqllocaldb;Database=GmaAuthAdminEndpointTests;Trusted_Connection=True;")
        ]);
        builder.Services.AddGmaAdministrationApi(builder.Configuration);
        builder.AddGmaInfrastructure();
        builder.AddAuthAdminApiModule(AuthProfile.Global("global"));

        await using WebApplication app = builder.Build();
        app.MapAdminApiModules();

        RouteEndpoint[] endpoints = [.. ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(dataSource => dataSource.Endpoints)
            .OfType<RouteEndpoint>()];
        RouteEndpoint createMember = GetEndpoint(endpoints, "/api/admin/auth/members/", "POST");
        Type requestType = Assert.IsType<IAcceptsMetadata>(
            createMember.Metadata.GetMetadata<IAcceptsMetadata>(),
            exactMatch: false).RequestType!;

        Assert.Equal(typeof(AuthAdminApiModule.CreateAdminMemberRequest), requestType);
        Assert.Equal(typeof(UsernameType), requestType.GetProperty("UsernameType")!.PropertyType);
        AssertProduces(createMember, StatusCodes.Status200OK, typeof(AuthAdminApiModule.AdminCreatedMemberApiResponse));
        AssertProduces(
            GetEndpoint(endpoints, "/api/admin/auth/members/{memberId:guid}", "GET"),
            StatusCodes.Status200OK,
            typeof(AdminMemberDetails));
        AssertProduces(
            GetEndpoint(endpoints, "/api/admin/auth/members/{memberId:guid}/disable", "POST"),
            StatusCodes.Status204NoContent);
        AssertProduces(
            GetEndpoint(endpoints, "/api/admin/auth/members/{memberId:guid}/revoke-sessions", "POST"),
            StatusCodes.Status200OK,
            typeof(AdminRevokeSessionsResponse));

        await AssertNoStoreOnDeniedAdminRequest(
            app,
            createMember,
            """{"username":"user@example.com","usernameType":"email","password":null,"generatePassword":true}""");
        await AssertNoStoreOnDeniedAdminRequest(
            app,
            GetEndpoint(endpoints, "/api/admin/auth/members/{memberId:guid}/reset-password", "POST"),
            """{"newPassword":null,"generatePassword":true,"confirmed":true}""",
            new RouteValueDictionary { ["memberId"] = Guid.NewGuid().ToString() });
    }

    private static RouteEndpoint GetEndpoint(RouteEndpoint[] endpoints, string route, string method) =>
        Assert.Single(endpoints, endpoint =>
            string.Equals(endpoint.RoutePattern.RawText, route, StringComparison.Ordinal) &&
            endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(method, StringComparer.Ordinal) == true);

    private static void AssertProduces(RouteEndpoint endpoint, int statusCode, Type? responseType = null)
    {
        IProducesResponseTypeMetadata metadata = Assert.Single(
            endpoint.Metadata.GetOrderedMetadata<IProducesResponseTypeMetadata>(),
            item => item.StatusCode == statusCode);

        if (responseType is not null)
        {
            Assert.Equal(responseType, metadata.Type);
        }
    }

    private static async Task AssertNoStoreOnDeniedAdminRequest(
        WebApplication app,
        RouteEndpoint endpoint,
        string requestJson,
        RouteValueDictionary? routeValues = null)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, "test-admin")],
                authenticationType: "test"))
        };
        httpContext.Request.Method = "POST";
        httpContext.Request.ContentType = "application/json";
        httpContext.Request.RouteValues = routeValues ?? [];
        byte[] requestBody = Encoding.UTF8.GetBytes(requestJson);
        httpContext.Request.ContentLength = requestBody.Length;
        httpContext.Request.Body = new MemoryStream(requestBody);
        httpContext.Response.Body = new MemoryStream();
        httpContext.Features.Set<IHttpRequestBodyDetectionFeature>(new RequestBodyDetectionFeature());

        await endpoint.RequestDelegate!(httpContext);

        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        Assert.Equal("no-store", httpContext.Response.Headers.CacheControl);
        Assert.Equal("no-cache", httpContext.Response.Headers.Pragma);
    }

    private sealed class RequestBodyDetectionFeature : IHttpRequestBodyDetectionFeature
    {
        public bool CanHaveBody => true;
    }

    private static void AssertNoStore(HttpResponseMessage response)
    {
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.Select(value => value.Name));
    }
}
