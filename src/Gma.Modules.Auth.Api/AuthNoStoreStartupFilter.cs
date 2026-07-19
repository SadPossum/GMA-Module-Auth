namespace Gma.Modules.Auth.Api;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

internal sealed class AuthNoStoreStartupFilter : IStartupFilter
{
    private static readonly PathString AuthPath = new("/api/auth");

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        ArgumentNullException.ThrowIfNull(next);

        return applicationBuilder =>
        {
            applicationBuilder.Use(nextMiddleware => context =>
            {
                if (context.Request.Path.StartsWithSegments(AuthPath))
                {
                    context.Response.OnStarting(static state =>
                    {
                        var response = (HttpResponse)state;
                        response.Headers.CacheControl = "no-store";
                        response.Headers.Pragma = "no-cache";
                        return Task.CompletedTask;
                    }, context.Response);
                }

                return nextMiddleware(context);
            });

            next(applicationBuilder);
        };
    }
}
