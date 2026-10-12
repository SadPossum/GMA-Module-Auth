namespace Gma.Modules.Auth.Api;

using System.Text.Json;
using System.Text.Json.Serialization;
using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Infrastructure.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

public sealed partial class AuthModule
{
    private static readonly JsonSerializerOptions RememberedRequestJson = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };

    private static void MapRememberedBrowserEndpoints(RouteGroupBuilder auth, bool requireScope)
    {
        IServiceProvider services = ((IEndpointRouteBuilder)auth).ServiceProvider;
        if (!services.GetRequiredService<IOptions<RememberedBrowserOptions>>().Value.Enabled)
        {
            return;
        }

        if (services.GetRequiredService<IOptions<AuthBearerAdmissionOptions>>().Value.Mode != AuthBearerAdmissionMode.ActiveSession)
        {
            throw new InvalidOperationException("Remembered-browser authentication requires active-session admission.");
        }

        RouteGroupBuilder group = auth.MapGroup("/browser/remembered");
        RouteHandlerBuilder current = group.MapGet("/current", async (
            HttpContext context,
            IRememberedBrowserService service,
            RememberedBrowserRequestContext request,
            RememberedBrowserHttpSecurity security,
            CancellationToken cancellationToken) =>
        {
            RememberedBrowserCurrentResponse response = await service.CurrentAsync(cancellationToken).ConfigureAwait(false);
            SetNoStoreHeaders(context);
            if (request.DeviceCredential is not null && response.State is RememberedBrowserState.Missing or RememberedBrowserState.Revoked)
            {
                RememberedBrowserHttpSecurity.ClearCookies(context, device: true);
            }

            return Results.Ok(security.WithCsrf(response, request.DeviceCredential));
        }).WithName("GetRememberedBrowserCurrent").Produces<RememberedBrowserCurrentResponse>();
        RequireScopeWhenNeeded(current, requireScope);

        RouteHandlerBuilder outcome = group.MapGet("/operations/{operationId:guid}", async (
            Guid operationId,
            HttpContext context,
            IRememberedBrowserService service,
            RememberedBrowserRequestContext request,
            RememberedBrowserHttpSecurity security,
            CancellationToken cancellationToken) =>
        {
            SetNoStoreHeaders(context);
            RememberedBrowserOperationResponse result = await service.OutcomeAsync(operationId, cancellationToken).ConfigureAwait(false);
            return Results.Json(result with { Current = security.WithCsrf(result.Current, request.DeviceCredential) },
                statusCode: RememberedStatus(result.Outcome));
        }).WithName("GetRememberedBrowserOperation").Produces<RememberedBrowserOperationResponse>()
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status401Unauthorized)
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status404NotFound)
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status409Conflict);
        RequireScopeWhenNeeded(outcome, requireScope);

        RouteHandlerBuilder bootstrap = group.MapPost("/device", async (HttpContext context) =>
        {
            if (context.Request.ContentLength is > 0 || context.Request.Headers.ContainsKey("Transfer-Encoding"))
            {
                return Results.BadRequest();
            }

            if (GetMemberId(context.User) is not { } member || GetSessionId(context.User) is not { } session)
            {
                return Results.Unauthorized();
            }

            IResult result = await RunRememberedAsync(context,
                new(RememberedBrowserOperationKind.Device, Guid.Empty, 0, member, session)).ConfigureAwait(false);
            return result;
        }).RequireAuthorization().WithName("CreateRememberedBrowserDevice")
            .Produces<RememberedBrowserCurrentResponse>();
        RequireScopeWhenNeeded(bootstrap, requireScope);

        MapRememberedMutation<RememberBrowserAccountRequest>(group, "/remember", "RememberBrowserAccount",
            (body, context) => new(RememberedBrowserOperationKind.Remember, body.OperationId, body.ExpectedGeneration,
                GetMemberId(context.User), GetSessionId(context.User), Pin: body.Pin, Label: body.Label, Consent: body.Consent), requireScope)
            .RequireAuthorization();
        MapRememberedMutation<SelectRememberedAccountRequest>(group, "/select", "SelectRememberedAccount",
            (body, _) => new(RememberedBrowserOperationKind.Select, body.OperationId, body.ExpectedGeneration,
                ProofId: body.ProofId, Pin: body.Pin), requireScope);
        MapRememberedMutation<RecoverRememberedOperationRequest>(group, "/recover", "RecoverRememberedOperation",
            (body, _) => new(RememberedBrowserOperationKind.Recover, body.OperationId, body.ExpectedGeneration, Pin: body.Pin), requireScope);
        MapRememberedMutation<RememberedBrowserTransitionRequest>(group, "/lock", "LockRememberedBrowser",
            (body, _) => new(RememberedBrowserOperationKind.Lock, body.OperationId, body.ExpectedGeneration), requireScope);
        MapRememberedMutation<RememberedBrowserTransitionRequest>(group, "/begin-sign-in", "BeginRememberedBrowserSignIn",
            (body, _) => new(RememberedBrowserOperationKind.BeginSignIn, body.OperationId, body.ExpectedGeneration), requireScope);
        MapRememberedMutation<RememberedBrowserTransitionRequest>(group, "/cancel-sign-in", "CancelRememberedBrowserSignIn",
            (body, _) => new(RememberedBrowserOperationKind.CancelSignIn, body.OperationId, body.ExpectedGeneration), requireScope);
        MapRememberedMutation<ForgetRememberedAccountRequest>(group, "/forget", "ForgetRememberedAccount",
            (body, _) => new(RememberedBrowserOperationKind.Forget, body.OperationId, body.ExpectedGeneration, ProofId: body.ProofId), requireScope);
        MapRememberedMutation<RememberedBrowserTransitionRequest>(group, "/forget-device", "ForgetRememberedBrowser",
            (body, _) => new(RememberedBrowserOperationKind.ForgetDevice, body.OperationId, body.ExpectedGeneration), requireScope);
        MapRememberedMutation<RememberedBrowserActivityRequest>(group, "/activity", "RecordRememberedBrowserActivity",
            (body, context) => new(RememberedBrowserOperationKind.Activity, Guid.Empty, body.ExpectedGeneration,
                GetMemberId(context.User), GetSessionId(context.User) == body.SessionId ? body.SessionId : null), requireScope)
            .RequireAuthorization();
    }

    private static RouteHandlerBuilder MapRememberedMutation<T>(
        RouteGroupBuilder group,
        string pattern,
        string name,
        Func<T, HttpContext, RememberedBrowserOperation> operation,
        bool requireScope)
        where T : class
    {
        RouteHandlerBuilder endpoint = group.MapPost(pattern, async (HttpContext context) =>
        {
            T? body = await ReadRememberedBodyAsync<T>(context).ConfigureAwait(false);
            if (body is null)
            {
                return Results.BadRequest();
            }

            return await RunRememberedAsync(context, operation(body, context)).ConfigureAwait(false);
        }).WithName(name).Accepts<T>("application/json").Produces<RememberedBrowserOperationResponse>()
            .Produces(StatusCodes.Status400BadRequest).Produces(StatusCodes.Status403Forbidden)
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status401Unauthorized)
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status404NotFound)
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status409Conflict)
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status429TooManyRequests)
            .Produces<RememberedBrowserOperationResponse>(StatusCodes.Status503ServiceUnavailable);
        RequireScopeWhenNeeded(endpoint, requireScope);
        return endpoint;
    }

    private static async Task<IResult> RunRememberedAsync(HttpContext context, RememberedBrowserOperation operation)
    {
        IRequestDispatcher dispatcher = context.RequestServices.GetRequiredService<IRequestDispatcher>();
        Result<RememberedBrowserCompletion> result = await dispatcher.SendAsync(new RememberedBrowserCommand(operation),
            context.RequestAborted).ConfigureAwait(false);
        if (result.IsFailure)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        RememberedBrowserCompletion completion = result.Value;
        RememberedBrowserRequestContext request = context.RequestServices.GetRequiredService<RememberedBrowserRequestContext>();
        RememberedBrowserHttpSecurity security = context.RequestServices.GetRequiredService<RememberedBrowserHttpSecurity>();
        SetNoStoreHeaders(context);
        RememberedBrowserHttpSecurity.WriteCookies(context, completion);
        if (completion.Response.Outcome == RememberedBrowserOutcome.Applied &&
            operation.Kind is RememberedBrowserOperationKind.Lock or RememberedBrowserOperationKind.BeginSignIn or
                RememberedBrowserOperationKind.CancelSignIn or RememberedBrowserOperationKind.Forget or RememberedBrowserOperationKind.ForgetDevice)
        {
            RememberedBrowserHttpSecurity.ClearCookies(context, operation.Kind == RememberedBrowserOperationKind.ForgetDevice);
        }

        RememberedBrowserCurrentResponse current = security.WithCsrf(completion.Response.Current,
            completion.DeviceCredential ?? request.DeviceCredential);
        return operation.Kind == RememberedBrowserOperationKind.Device && completion.Response.Outcome == RememberedBrowserOutcome.Applied
            ? Results.Ok(current)
            : Results.Json(completion.Response with { Current = current }, statusCode: RememberedStatus(completion.Response.Outcome));
    }

    private static async Task<T?> ReadRememberedBodyAsync<T>(HttpContext context) where T : class
    {
        if (!context.Request.HasJsonContentType() || context.Request.ContentLength is > 4096)
        {
            return null;
        }

        byte[] bytes = new byte[4097];
        int length = 0;
        while (length < bytes.Length)
        {
            int read = await context.Request.Body.ReadAsync(bytes.AsMemory(length), context.RequestAborted).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            length += read;
        }

        if (length is 0 or > 4096)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(bytes.AsSpan(0, length), RememberedRequestJson);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static int RememberedStatus(RememberedBrowserOutcome outcome) => outcome switch
    {
        RememberedBrowserOutcome.Applied => StatusCodes.Status200OK,
        RememberedBrowserOutcome.AuthenticationRequired or RememberedBrowserOutcome.PinRejected => StatusCodes.Status401Unauthorized,
        RememberedBrowserOutcome.RateLimited => StatusCodes.Status429TooManyRequests,
        RememberedBrowserOutcome.Unavailable => StatusCodes.Status503ServiceUnavailable,
        RememberedBrowserOutcome.NotFound => StatusCodes.Status404NotFound,
        _ => StatusCodes.Status409Conflict
    };
}
