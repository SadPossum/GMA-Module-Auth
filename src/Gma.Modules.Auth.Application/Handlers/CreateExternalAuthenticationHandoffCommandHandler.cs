namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;

internal sealed class CreateExternalAuthenticationHandoffCommandHandler(
    IExternalAuthenticationHandoffService handoffService)
    : ICommandHandler<CreateExternalAuthenticationHandoffCommand, ExternalAuthenticationHandoff>
{
    public async Task<Result<ExternalAuthenticationHandoff>> HandleAsync(
        CreateExternalAuthenticationHandoffCommand command,
        CancellationToken cancellationToken) =>
        Result.Success(await handoffService.CreateAsync(
            command.Identity,
            command.Intent,
            command.ReturnUrl,
            command.TargetMemberId,
            command.TargetSessionId,
            cancellationToken).ConfigureAwait(false));
}
