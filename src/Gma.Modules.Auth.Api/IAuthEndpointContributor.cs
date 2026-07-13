namespace Gma.Modules.Auth.Api;

using Gma.Modules.Auth.Contracts;
using Microsoft.AspNetCore.Routing;

public interface IAuthEndpointContributor
{
    void MapEndpoints(RouteGroupBuilder authGroup, AuthProfile profile);
}
